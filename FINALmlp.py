import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import matplotlib.pyplot as plt
import numpy as np
import pickle
import pandas
import glob
import winreg
import netifaces
import csv
import pyshark
import time
import datetime

# !wget http://205.174.165.80/CICDataset/CICDDoS2019/Dataset/CSVs/CSV-03-11.zip
# !unzip CSV-03-11.zip

datasets_dic = {}
count = 0

path = r'./03-11'
all_files = glob.glob(path + "/*.csv")

for file in all_files:
    print(file)
    chunks = pd.read_csv(file, chunksize=500000)
    chunks_dic = {}
    count = 0
    for chunk in chunks:
        if(count == 1):
            break  
        chunks_dic[count] = chunk 
        count += 1
    # print(count)
    datasets_dic[file] = pd.concat(chunks_dic)

initial_df = pd.concat(datasets_dic)
label_df = pd.DataFrame(initial_df[' Label'].value_counts()).reset_index()

def z_score(input_df):
    # copy the data
    df_z_scaled = input_df

    # apply normalization techniques
    for column in df_z_scaled.columns:
        df_z_scaled[column] = (df_z_scaled[column] -
                               df_z_scaled[column].mean()) / df_z_scaled[column].std()    

    # view normalized data   
    return df_z_scaled

#SAMPLING

attack_sample_df_dic = {}
attack_df = initial_df[ initial_df[' Label'] != 'BENIGN' ]
for label in label_df['index']:
  attack_sample_df_dic[label] = attack_df[attack_df[' Label'] == label][:300]

attack_sample_df = pd.concat(attack_sample_df_dic)
# 10% attacks vs 90% benign
BENIGN_sample_df = initial_df[initial_df[' Label'] == 'BENIGN'][:18900]

sampled_df_1 =  pd.concat([attack_sample_df, BENIGN_sample_df])

#PREPROCESSING

df = sampled_df_1.copy()
df_1 = df.replace(np.inf, np.nan)   #delete null and inf values
df_2 = df_1.dropna(axis=0)
df_std = pd.DataFrame(df_2.std(), columns = ['value'])
unchange_col = df_std[df_std['value'] == 0].index
df_3 = df_2.drop(unchange_col, axis=1)     #delete unchanged features
df_object = df_3.select_dtypes(include='object')    #delete useless features
df_4 = df_3.drop(['Flow ID', ' Source IP', ' Destination IP'], axis=1)
df_4.drop([' Timestamp'], axis=1, inplace = True)
df_4.drop(['SimillarHTTP'], axis=1, inplace = True)
df_4.drop(['Unnamed: 0'], axis=1, inplace = True)
df_corr = df_4.corr().abs()     #delete highly correlated features
high_corr = df_corr.where(np.triu(np.ones(df_corr.shape),k=1).astype(np.bool))
to_drop = [column for column in high_corr.columns if any(high_corr[column] > 0.90)]
df_5 = df_4.drop(to_drop, axis=1)
df_corr = df_5.corr().abs()
df_corr.loc[1, 1] = 1
df_5 = df_4.reset_index()    #delete features with many neg values
df_5 = df_5.drop(['index'], axis = 1)
df_5 = df_5.sample(frac = 1)
negative_df = df_5 == -1
number_of_negative_df = pd.DataFrame(negative_df.sum(), columns = ['count']).reset_index()
df_size = len(df_5)
to_drop = number_of_negative_df[number_of_negative_df['count'] > 1]['index'].values
df_6 = df_5.drop(to_drop, axis = 1)
df_6 = df_6.reset_index()
df_6 = df_6.drop(['index'], axis = 1)
df_6 = df_6.sample(frac = 1)
zero_df = df_6 == 0     #Delete features whith more than 85% zero value
number_of_zero_df = pd.DataFrame(zero_df.sum(), columns = ['count']).reset_index()
df_size = len(df_6)
to_drop = number_of_zero_df[number_of_zero_df['count'] > (df_size * 0.85)]['index']
df_7 = df_6.drop(to_drop, axis = 1)
df_8 = df_7.copy()
df_9 = df_8.sample(frac = 1)    #shuffle df
df_10 = pd.get_dummies(df_9, columns = [' Protocol'])   #Encoding categorical data
destination_port_df = pd.DataFrame(df_10[' Destination Port'].value_counts())
dp_df_size = len(destination_port_df)
unmost_port = destination_port_df.tail(dp_df_size - 10).index
df_11 = df_10.copy()
df_11 = df_10.replace(to_replace = unmost_port, value =99999)
df_11 = pd.get_dummies(df_11, columns = [' Destination Port'])
Source_Port_df = pd.DataFrame(df_11[' Source Port'].value_counts())
sp_df_size = len(Source_Port_df)
unmost_port = Source_Port_df.tail(sp_df_size - 10).index
df_12 = df_11.copy()
df_12[' Source Port'] = df_11[' Source Port'].replace(to_replace = unmost_port, value =99999)
df_12 = pd.get_dummies(df_12, columns = [' Source Port'])
df_13 = z_score(df_12.drop([' Label'], axis = 1))       #z-score normalization
df_13[' Label'] = df_12[' Label']
final_df = df_13.copy()
final_01_df = final_df.copy()
final_01_df[' Label'] = final_df[' Label'] != 'BENIGN'


# def preprocess_data(data):
#     # Check for NaN values and drop rows containing NaN
#     data = data.dropna()

#     # Check for infinity values and replace them with a large finite value
#     data = data.replace([np.inf, -np.inf], np.finfo(np.float64).max)

#     # Normalize numerical features
#     scaler = StandardScaler()
#     data[['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time']] = scaler.fit_transform(data[['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time']])
    
#     return data

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

    X = final_01_df.drop([' Label'], axis = 1)
    y = final_01_df[' Label']

    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)

    # Initialize MLP classifier
    mlp = MLPClassifier(hidden_layer_sizes=(100, 100), 
                        activation='relu', 
                        solver='sgd', 
                        max_iter=1000, 
                        alpha=0.0001, 
                        batch_size='auto', 
                        verbose=True,
                        shuffle=True)

    # Train MLP model
    mlp.fit(X_train, y_train)
    
    # Make predictions on test set
    predictions = mlp.predict(X_test)
    
    # Evaluate model performance
    print("Number of Iterations: ", mlp.n_iter_)
    visualize_confusion_matrix(y_test, predictions)
    print("Classification Report: ", "\n", classification_report(y_test, predictions))

### LIVE STUFF #################################
    
# allows the program to differentiate between ipv4 and ipv6, 
# needed for correct parsing of packets
def get_ip_layer_name(pkt):
    for layer in pkt.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

# allows retrieving the names of network interfaces based on their GUIDs
# use : identifying and selecting specific network interfaces in Windows environments.
def interface_names(interface_guids):
    interface_names = ['(unknown)' for _ in range(len(interface_guids))]
    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(interface_guids)):
        try:
            reg_subkey = winreg.OpenKey(reg_key, interface_guids[i] + r'\Connection')
            interface_names[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            pass
    return interface_names

def interface_choice():
    for i, value in enumerate(interface_names(netifaces.interfaces())):
        print(i, value)
    print('\n')
    iface = input("Please select interface: ")
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
    data = pandas.read_csv('LiveAnn.csv', delimiter=',')
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
    
    # Gather packet information 
    # packet_info(cap)
    
    # Gather data and write to CSV
    # csvgather(cap)
    
    # Train or load the neural network model on existing CSV 
    mlp_model = MLP()

    # Choose network interface
    cap = interface_choice()
    
    # Gather live packet data and write to CSV
    csv_interval_gather(cap)
    
    # Perform live prediction using the trained model
    MLP_Live_predict(cap, mlp_model)


# Define allowed IPs globally
# examples:
allowed_IP = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']

if __name__ == "__main__":
    main()