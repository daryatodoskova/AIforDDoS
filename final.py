#!/usr/bin/env python
# coding: utf-8

import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import numpy as np
import pickle
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

file_path = "/home/yazid/Downloads/tcpDDOS.csv"

initial_df = pd.read_csv(file_path)

label_df = pd.DataFrame(initial_df['label'])

label_counts = initial_df['label']

labels_attack = label_counts[label_counts.isna()]
labels_benign = label_counts[~label_counts.isna()]

def z_score(input_df):
    # copy the data
    df_z_scaled = input_df

    # apply normalization techniques
    for column in df_z_scaled.columns:
        df_z_scaled[column] = (df_z_scaled[column] -
                               df_z_scaled[column].mean()) / df_z_scaled[column].std()    

    # view normalized data   
    return df_z_scaled

new_df = initial_df.copy()

# Replace empty strings and NaN values in the 'label' column with 'attack'
new_df['label'] = new_df['label'].fillna('attack')

# Replace all remaining labels (excluding 'attack') with 'benign'
new_df.loc[new_df['label'] != 'attack', 'label'] = 'benign'

label_counts = new_df['label'].value_counts()

# plt.figure(figsize=(8, 8))
# plt.pie(label_counts, labels=label_counts.index, autopct='%1.1f%%', startangle=140)
# plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
# plt.show()

label_counts = pd.DataFrame(new_df['label'].value_counts()).reset_index()

#SAMPLING
attack_sample_df_dic = {}
labels = label_counts['label']
attack_df = new_df[ new_df['label'] != 'benign' ]
for label in labels:
    #5% of attacks
    attack_sample_df_dic[label] = attack_df[attack_df['label'] == label][:1000]

attack_sample_df = pd.concat(attack_sample_df_dic)
# 10% attacks vs 90% benign
BENIGN_sample_df = new_df[new_df['label'] == 'benign'][:19000]

sampled_df_1 =  pd.concat([attack_sample_df, BENIGN_sample_df])

sampled_label_counts = sampled_df_1['label'].value_counts()

# Create a pie chart for the sampled dataset
# plt.figure(figsize=(8, 8))
# plt.pie(sampled_label_counts, labels=sampled_label_counts.index, autopct='%1.1f%%', startangle=140)
# plt.title('Sampled Label Distribution')
# plt.axis('equal')  
# plt.show()

# ### Preprocessing

df = sampled_df_1.copy()

# df_1 = df.replace(np.inf, np.nan)
# df_1.isnull().sum().sum()
#sns.heatmap(df_1 == np.nan)

# df_2 = df_1.dropna(axis=0)
# df_2.isnull().sum().sum()

# df_std = pd.DataFrame(df.std(), columns = ['value'])
# unchange_col = df_std[df_std['value'] == 0].index
# unchange_col
# df_3 = df_2.drop(unchange_col, axis=1)
# df_3

df_object = df.select_dtypes(include='object')

df_4 = df.drop(['ACK Flag Count', 'URG Flag Count'], axis=1)

df_4['Time'].value_counts()

df_4.drop(['Time'], axis=1, inplace = True)

df_4['Total Length of Bwd Packets'].value_counts()

df_4.drop(['Total Length of Bwd Packets'], axis=1, inplace = True)

# Select only numeric columns from df_4
df_numeric = df_4.select_dtypes(include=[np.number])

# Compute the correlation matrix of the numeric DataFrame
df_corr = df_numeric.corr().abs()

# Continue with your existing code for plotting
corr_val = df_corr.values
corr_val[1][1] = 1  # You might not need this line depending on your intention. It sets the diagonal value to 1, but it's already 1 for correlation matrices.
mask = np.zeros_like(corr_val)
mask[np.triu_indices_from(mask)] = True
# with sns.axes_style("white"):
#     f, ax = plt.subplots(figsize=(7, 7))
#     ax = sns.heatmap(corr_val, mask=mask, vmax=0.9, square=True)

high_corr = df_corr.where(np.triu(np.ones(df_corr.shape), k=1).astype(np.bool_))

to_drop = [column for column in high_corr.columns if any(high_corr[column] > 0.90)]

df_5 = df_4.drop(to_drop, axis=1)

df_numeric = df_5.select_dtypes(include=[np.number])
df_corr = df_numeric.corr().abs()

corr_val = df_corr.values
mask = np.zeros_like(corr_val, dtype=np.bool_)
mask[np.triu_indices_from(mask, k=1)] = True  # k=1 to exclude the main diagonal

# with sns.axes_style("white"):
#     f, ax = plt.subplots(figsize=(7, 7))
#     heatmap = sns.heatmap(corr_val, mask=mask, vmax=0.9, square=True, ax=ax, annot=True, fmt=".2f", cmap="coolwarm")
#     heatmap.set_title('Correlation Heatmap', fontdict={'fontsize':12}, pad=12)

df_corr.loc[1, 1] = 1

# df_5 = df_4.reset_index()
# df_5 = df_5.drop(['No.'], axis = 1)
# df_5 = df_5.sample(frac = 1)
# sns.heatmap(df_5 == -1)

# negative_df = df_5 == -1
# number_of_negative_df = pd.DataFrame(negative_df.sum(), columns = ['count']).reset_index()
# df_size = len(df_5)
# to_drop = number_of_negative_df[number_of_negative_df['count'] > 1]['index'].values
# to_drop

df_6 = df_5.reset_index()
df_6 = df_6.drop(['index'], axis = 1)
df_6 = df_6.sample(frac = 1)

# sns.heatmap(df_6 == 0)

# zero_df = df_6 == 0
# number_of_zero_df = pd.DataFrame(zero_df.sum(), columns = ['count']).reset_index()
# df_size = len(df_6)
# to_drop = number_of_zero_df[number_of_zero_df['count'] > (df_size * 0.85)]['index']
# to_drop
# df_7 = df_6.drop(to_drop, axis = 1)

df_8 = df_6.copy()

df_9 = df_8.sample(frac = 1)

# sns.heatmap(df_9 == 0)

destination_port_df = pd.DataFrame(df_9['dest port'].value_counts())
dp_df_size = len(destination_port_df)
unmost_port = destination_port_df.tail(dp_df_size - 10).index
df_11 = df_9.copy()
df_11 = df_9.replace(to_replace = unmost_port, value =99999)
df_11 = pd.get_dummies(df_11, columns = ['dest port'])

Source_Port_df = pd.DataFrame(df_11['source port'].value_counts())
sp_df_size = len(Source_Port_df)
unmost_port = Source_Port_df.tail(sp_df_size - 10).index
df_12 = df_11.copy()
df_12['source port'] = df_11['source port'].replace(to_replace = unmost_port, value =99999)
df_12 = pd.get_dummies(df_12, columns = ['source port'])

# df_12_encoded = pd.get_dummies(df_12, columns=['Source', 'Destination'])
# df_12_encoded
df_12_dropped = df_12.drop(['Source', 'Destination'], axis=1)

df_13_encoded = pd.get_dummies(df_12_dropped, columns = ['Protocol'])

string_columns = df_13_encoded.select_dtypes(include=['object']).columns

# print("Columns with string values:")
# print(string_columns)

columns_to_encode = ['Info', 'label', 'protocol']

# Initialize LabelEncoder
label_encoders = {}

# Apply LabelEncoder to each column
for column in columns_to_encode:
    label_encoders[column] = LabelEncoder()
    df_13_encoded[column] = label_encoders[column].fit_transform(df_13_encoded[column])

df_13 = z_score(df_13_encoded.drop(['label'], axis = 1))
df_13['label'] = df_13_encoded['label']

final_df = df_13.copy()
final_df['label'].value_counts()

# ## Predictions/testing

def visualize_confusion_matrix(y_true, y_pred):
    conf_matrix = confusion_matrix(y_true, y_pred)
    # Print the confusion matrix using Matplotlib
    fig, ax = plt.subplots(figsize=(5, 5))
    ax.matshow(conf_matrix, cmap=plt.cm.Oranges, alpha=0.3)
    for i in range(conf_matrix.shape[0]):
        for j in range(conf_matrix.shape[1]):
            ax.text(x=j, y=i,s=conf_matrix[i, j], va='center', ha='center', size='x-large')

    plt.xlabel('Predictions', fontsize=18)
    plt.ylabel('Actuals', fontsize=18)
    plt.title('Confusion Matrix', fontsize=18)
    plt.show()

def MLP():
    X = final_df.drop(['label'], axis = 1)
    y = final_df['label']
    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)
    X_train.fillna(X_train.mean(), inplace=True)
    
    mlp = MLPClassifier(hidden_layer_sizes=(100, 100), 
                        activation='relu', 
                        solver='sgd', 
                        max_iter=1000, 
                        alpha=0.0001, 
                        batch_size='auto', 
                        verbose=False)
    
    mlp.fit(X_train, y_train)
    
    X_test.fillna(X_test.mean(), inplace=True)
    predictions = mlp.predict(X_test)
    
    # Evaluate model performance
    print("Number of Iterations: ", mlp.n_iter_)
    visualize_confusion_matrix(y_test, predictions)
    print("Accuracy: ", accuracy_score(y_test, predictions))
    print("Classification Report: ", "\n", classification_report(y_test, predictions))

# # Partie 2 : En temps réel

import pyshark
import time
import csv
import netifaces
import time
import datetime

# allows the program to differentiate between ipv4 and ipv6, 
# needed for correct parsing of packets
def get_ip_layer_name(pkt):
    for layer in pkt.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

def interface_names():
    return netifaces.interfaces()

def interface_choice():
    interfaces = interface_names()
    for i, interface in enumerate(interfaces):
        print(f"{i}: {interface}")
    iface_index = int(input("Please select an interface by index: "))
    iface = interfaces[iface_index]
    cap = pyshark.LiveCapture(interface=iface)
    cap.sniff_continuously(packet_count=None)
    return cap

# captures packet info over a specified time interval from a live network interface
# and writes it to a CSV file
def csv_interval_gather(cap):    #cap = a live packet capture
    start_time = time.time()
    with open('LiveAnn.csv', 'w', newline='') as csvfile:
        filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        filewriter.writerow(['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                             'Packet Length', 'Packets/Time'])

        i = 0
        start = time.time()
        for pkt in cap:
            end = time.time()
            # limits the packet capture to 60 sec
            if end - start >= 60:
                break
            try:
            # processes packet
                if pkt.highest_layer != 'ARP':
                    ip = None
                    ip_layer = get_ip_layer_name(pkt)
                    if ip_layer == 4:
                        ip = pkt.ip
                    elif ip_layer == 6:
                        ip = pkt.ipv6

                    transport_layer = pkt.transport_layer if pkt.transport_layer else 'None'

                    ipcat = 1 if ip.src not in allowed_IP else 0
                    srcport = pkt[pkt.transport_layer].srcport if pkt.transport_layer else 0
                    dstport = pkt[pkt.transport_layer].dstport if pkt.transport_layer else 0

                    filewriter.writerow([pkt.highest_layer, transport_layer, ip.src, ip.dst, srcport, dstport,
                                         pkt.length, i / (time.time() - start_time)])
                    i += 1
                else:
                    arp = pkt.arp
                    ipcat = 1 if arp.src_proto_ipv4 not in allowed_IP else 0

                    filewriter.writerow([pkt.highest_layer, 'ipv4', ipcat, arp.dst_proto_ipv4, 0, 0,
                                         pkt.length, i / (time.time() - start_time)])
                    i += 1
            except (UnboundLocalError, AttributeError):
            # skips any packet that has errors
                pass

def LiveLabelEncoding(data):
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
    le = LabelEncoder()
    for feature in columnsToEncode:
        try:
            data[feature] = le.fit_transform(data[feature])
        except:
            print('Error: ' + feature)
    return data

def MLP_Live_predict(cap, modelname):            
    data = pd.read_csv('LiveAnn.csv', delimiter=',')
    X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
              'Packet Length', 'Packets/Time']]

    loaded_model = pickle.load(open(modelname, 'rb'))
    predictions = loaded_model.predict(X)

    hostile = 0
    safe = 0
    for check in predictions:
        if check == 1:
            hostile += 1
        else:
            safe += 1
    print("Safe Packets: ", safe)
    print("Possible Hostile Packets: ", hostile)
    print(100 * hostile / (safe + hostile))
    
    if hostile >= (safe + hostile) / 2:
        print("DDoS ATTACK DETECTED! @ ", datetime.datetime.now().strftime("%Y-%m-%d %H:%M"))

def main():
    
    # Train or load the neural network model on existing CSV 
    mlp_model = MLP()

    # Choose network interface
    cap = interface_choice()
    
    # Gather live packet data and write to CSV
    csv_interval_gather(cap)
    
    # Perform live prediction using the trained model
    MLP_Live_predict(cap, mlp_model)

allowed_IP = ['192.168.233.3', '192.168.233.4'] # victim and attacker

if __name__ == "__main__":
    main()
