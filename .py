import pandas as pd

def process_firewall_logs(file_path):
    """
    Process pfSense firewall logs and convert them to a structured DataFrame
    
    Parameters:
    file_path (str): Path to the firewall log file
    
    Returns:
    pandas.DataFrame: Structured firewall log data
    """
    # Define column names based on pfSense filterlog format
    columns = [
        'rule_number',
        'sub_rule_number',
        'anchor',
        'tracker',
        'interface',
        'reason',
        'action',
        'direction',
        'ip_version',
        'tos',
        'ecn',
        'ttl',
        'id',
        'offset',
        'flags',
        'protocol_id',
        'protocol',
        'length',
        'source_ip',
        'destination_ip',
        'source_port',
        'destination_port',
        'data_length'
    ]
    
    # Read the log file
    # Skip the first part of each line (timestamp and pfSense filterlog[xxxxx]:)
    # and split the remaining part by commas
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            # Extract the relevant part after 'filterlog[xxxxx]:'
            parts = line.strip().split('filterlog[')
            if len(parts) > 1:
                log_data = parts[1].split(':', 1)[1].strip().split(',')
                data.append(log_data)
    
    # Create DataFrame
    df = pd.DataFrame(data, columns=columns)
    
    # Add timestamp column from the original log
    timestamps = []
    with open(file_path, 'r') as file:
        for line in file:
            # Extract timestamp (first part of the line before filterlog)
            timestamp = ' '.join(line.split()[:3])
            timestamps.append(timestamp)
    
    df.insert(0, 'timestamp', timestamps)
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S')
    
    # Clean up numeric columns
    numeric_columns = ['rule_number', 'tracker', 'ttl', 'id', 'offset', 
                      'length', 'source_port', 'destination_port', 'data_length']
    for col in numeric_columns:
        df[col] = pd.to_numeric(df[col], errors='coerce')
    
    return df



df = process_firewall_logs('/kaggle/input/firewall-export-logs/firewall_export (1).log')

# View the first few rows and data types
print(df.head())
#print("\nDataset Info:")
#print(df.info())

import pandas as pd

def process_firewall_logs(file_path):
    """
    Process pfSense firewall logs and convert them to a structured DataFrame with specific columns
    and one-hot encoding for categorical variables
    
    Parameters:
    file_path (str): Path to the firewall log file
    
    Returns:
    pandas.DataFrame: Structured firewall log data with selected columns and encoded categorical variables
    """
    # Define initial column names based on pfSense filterlog format
    columns = [
        'rule_number',
        'sub_rule_number',
        'anchor',
        'tracker',
        'interface',
        'reason',
        'action',
        'direction',
        'ip_version',
        'tos',
        'ecn',
        'ttl',
        'id',
        'offset',
        'flags',
        'protocol_id',
        'protocol',
        'length',
        'source_ip',
        'destination_ip',
        'source_port',
        'destination_port',
        'data_length'
    ]
    
    # Read the log file
    data = []
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split('filterlog[')
            if len(parts) > 1:
                log_data = parts[1].split(':', 1)[1].strip().split(',')
                data.append(log_data)
    
    # Create initial DataFrame
    df = pd.DataFrame(data, columns=columns)
    
    # Select and rename required columns
    traffic_data = df[[
        'source_ip',
        'destination_ip',
        'source_port',
        'destination_port',
        'protocol',
        'action'
    ]].copy()
    
    # Rename columns to match the requested format
    traffic_data.columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'action']
    
    # Convert ports to numeric
    traffic_data['src_port'] = pd.to_numeric(traffic_data['src_port'], errors='coerce')
    traffic_data['dst_port'] = pd.to_numeric(traffic_data['dst_port'], errors='coerce')
    
    # Apply one-hot encoding to protocol and action columns
    traffic_data = pd.get_dummies(traffic_data, columns=['protocol', 'action'])
    
    return traffic_data



# Process the log file
traffic_data = process_firewall_logs('/kaggle/input/firewall-export-logs/firewall_export (1).log')

# View the results
print("First few rows:")
print(traffic_data.head())
print("\nColumn names:")
print(traffic_data.columns.tolist())
print("\nData types:")
print(traffic_data.dtypes)


import pandas as pd
from sklearn.cluster import KMeans
from sklearn.tree import DecisionTreeClassifier
import numpy as np

def analyze_network_traffic(traffic_data):
    """
    Analyze network traffic using both clustering and classification approaches
    
    Parameters:
    traffic_data (pd.DataFrame): Preprocessed traffic data with columns for src_ip, dst_ip, src_port, dst_port,
                                protocol_udp, and action_block
    
    Returns:
    dict: Dictionary containing analysis results and rule suggestions
    """
    # Create a copy of the data to avoid modifying the original
    analysis_data = traffic_data.copy()
    
    # Convert IP addresses to numerical values
    analysis_data['src_ip_num'] = pd.factorize(analysis_data['src_ip'])[0]
    analysis_data['dst_ip_num'] = pd.factorize(analysis_data['dst_ip'])[0]
    
    # 1. Clustering Analysis
    # Select features for clustering
    cluster_features = analysis_data[['src_port', 'dst_port', 'src_ip_num', 'dst_ip_num']]
    
    # Perform KMeans clustering
    kmeans = KMeans(n_clusters=3, random_state=42)
    analysis_data['cluster'] = kmeans.fit_predict(cluster_features)
    
    # Analyze clusters
    cluster_analysis = analysis_data.groupby('cluster').agg({
        'src_ip': 'nunique',
        'dst_ip': 'nunique',
        'src_port': ['mean', 'min', 'max'],
        'dst_port': ['mean', 'min', 'max']
    })
    
    # 2. Classification Analysis
    # Prepare features for decision tree
    feature_columns = ['src_port', 'dst_port', 'src_ip_num', 'dst_ip_num', 'protocol_udp']
    
    X = analysis_data[feature_columns]
    y = analysis_data['action_block']  # Using action_block as target
    
    # Train decision tree
    dt_model = DecisionTreeClassifier(max_depth=5, random_state=42)
    dt_model.fit(X, y)
    
    # Get feature importance
    feature_importance = pd.Series(
        dt_model.feature_importances_,
        index=feature_columns
    ).sort_values(ascending=False)
    
    # Generate rule suggestions based on analysis
    rule_suggestions = []
    
    # Analyze clusters for potential rules
    for cluster_id in range(3):
        cluster_data = analysis_data[analysis_data['cluster'] == cluster_id]
        
        # Calculate block rate (using action_block)
        block_rate = cluster_data['action_block'].mean()
        
        # If cluster has low block rate (high pass rate), suggest allowing
        if block_rate < 0.2:
            common_ports = cluster_data['dst_port'].mode().iloc[0]
            rule_suggestions.append(f"Consider creating ALLOW rule for destination port {common_ports} "
                                 f"(cluster {cluster_id} shows {(1-block_rate):.1%} legitimate traffic)")
        
        # If cluster has high block rate, suggest blocking
        elif block_rate > 0.8:
            common_ports = cluster_data['dst_port'].mode().iloc[0]
            rule_suggestions.append(f"Consider creating BLOCK rule for destination port {common_ports} "
                                 f"(cluster {cluster_id} shows {block_rate:.1%} suspicious traffic)")
    
    # Use feature importance to suggest additional rules
    for feature, importance in feature_importance.items():
        if importance > 0.1:  # Only suggest rules for important features
            if feature == 'protocol_udp':
                rule_suggestions.append(f"UDP protocol is a significant factor "
                                     f"(importance: {importance:.2f}). Consider reviewing UDP traffic rules.")
            elif feature in ['src_port', 'dst_port']:
                rule_suggestions.append(f"{feature.replace('_', ' ').title()} is a significant factor "
                                     f"(importance: {importance:.2f}). Consider port-based rules.")
    
    return {
        'cluster_analysis': cluster_analysis,
        'feature_importance': feature_importance,
        'rule_suggestions': rule_suggestions,
        'model': dt_model  # Return the trained model for potential future use
    }



results = analyze_network_traffic(traffic_data)

# Print the analysis results
print("\nCluster Analysis:")
print(results['cluster_analysis'])

print("\nFeature Importance:")
print(results['feature_importance'])

print("\nRule Suggestions:")
for suggestion in results['rule_suggestions']:
    print(f"- {suggestion}")



