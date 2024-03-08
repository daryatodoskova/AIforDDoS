import winreg
import netifaces
import pickle
import csv
import pyshark
import time
import datetime
import pandas
from sklearn.preprocessing import LabelEncoder

def get_ip_layer_name(pkt):
    for layer in pkt.layers:
        if layer._layer_name == 'ip':
            return 4
        elif layer._layer_name == 'ipv6':
            return 6

def packet_info(cap):
    start_time = time.time()
    try:
        i = 1
        for pkt in cap:
            i += 1
            try:
                if pkt.highest_layer != 'ARP':
                    ip = None
                    ip_layer = get_ip_layer_name(pkt)
                    if ip_layer == 4:
                        ip = pkt.ip
                    elif ip_layer == 6:
                        ip = pkt.ipv6
                    print('Packet %d' % i)
                    print(pkt.highest_layer)
                    print(pkt.transport_layer)
                    print('Time', time.strftime("%Y-%m-%d %H:%M:%S"))
                    print('Layer: ipv%d' % get_ip_layer_name(pkt))
                    print('Source IP:', ip.src)
                    print('Destination IP:', ip.dst)
                    print('Length: ', pkt.length)
                    try:
                        print('Source Port', pkt[pkt.transport_layer].srcport)
                        print('Destination Port', pkt[pkt.transport_layer].dstport)
                    except AttributeError:
                        print('Source Port: ', 0)
                        print('Destination Port: ', 0)
                    print(i / (time.time() - start_time))
                    print('')
                else:
                    arp = pkt.arp
                    print(pkt.highest_layer)
                    print(pkt.transport_layer)
                    print('Layer: ipv4')
                    print('Time', time.strftime("%Y-%m-%d %H:%M:%S"))
                    print('Source IP: ', arp.src_proto_ipv4)
                    print('Destination IP: ', arp.dst_proto_ipv4)
                    print('Length: ', pkt.length)
                    print('Source Port: ', 0)
                    print('Destination Port: ', 0)
                    print(i / (time.time() - start_time))
                    print()
            except (AttributeError, UnboundLocalError, TypeError):
                pass
        return
    except KeyboardInterrupt:
        pass

def csvgather(cap):
    start_time = time.time()
    with open('Data.csv', 'w', newline='') as csvfile:
        filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        filewriter.writerow(['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                             'Packet Length', 'Packets/Time', 'target'])

        i = 0
        for pkt in cap:
            try:
                if pkt.highest_layer != 'ARP':
                    ip = None
                    ip_layer = get_ip_layer_name(pkt)
                    if ip_layer == 4:
                        ip = pkt.ip
                    elif ip_layer == 6:
                        ip = pkt.ipv6
                    ipv = 0 if ip_layer == 4 else 1
                    transport_layer = pkt.transport_layer if pkt.transport_layer else 'None'

                    ipcat = 1 if ip.src not in allowed_IP else 0
                    target = 1 if ip.src not in allowed_IP else 0
                    srcport = pkt[pkt.transport_layer].srcport if pkt.transport_layer else 0
                    dstport = pkt[pkt.transport_layer].dstport if pkt.transport_layer else 0

                    filewriter.writerow([pkt.highest_layer, transport_layer, ip.src, ip.dst, srcport, dstport,
                                         pkt.length, i / (time.time() - start_time), target])
                    i += 1
                else:
                    arp = pkt.arp
                    ipcat = 1 if arp.src_proto_ipv4 not in allowed_IP else 0
                    target = 1 if arp.src_proto_ipv4 not in allowed_IP else 0

                    filewriter.writerow([pkt.highest_layer, 'ipv4', ipcat, arp.dst_proto_ipv4, 0, 0,
                                         pkt.length, i / (time.time() - start_time), target])
                    i += 1
            except (UnboundLocalError, AttributeError):
                pass

def int_names(int_guids):
    int_names = ['(unknown)' for _ in range(len(int_guids))]
    reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
    reg_key = winreg.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(int_guids)):
        try:
            reg_subkey = winreg.OpenKey(reg_key, int_guids[i] + r'\Connection')
            int_names[i] = winreg.QueryValueEx(reg_subkey, 'Name')[0]
        except FileNotFoundError:
            pass
    return int_names

def LabelEncoding(data):
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
    le = LabelEncoder()
    for feature in columnsToEncode:
        try:
            data[feature] = le.fit_transform(data[feature])
        except:
            print('Error: ' + feature)
    return data

def Load_model():
    filename = input("Model to load?")
    loaded_model = pickle.load(open(filename, 'rb'))
    print(loaded_model.coefs_)
    print(loaded_model.loss_)
    return loaded_model

def int_choice():
    for i, value in enumerate(int_names(netifaces.interfaces())):
        print(i, value)
    print('\n')
    iface = input("Please select interface: ")
    cap = pyshark.LiveCapture(interface=iface)
    cap.sniff_continuously(packet_count=None)
    return cap  

def MLP():
    l_data = input("Name of CSV file? ")
    load = input("Load model?")
    if load == 'y':
        mlp = Load_model()
    else:
        from sklearn.neural_network import MLPClassifier
        mlp = MLPClassifier(hidden_layer_sizes=(100, 100), activation='logistic', max_iter=1000, verbose=True,
                            tol=0.00000001, early_stopping=True, shuffle=True)

    data = pandas.read_csv(l_data, delimiter=',')
    data = LabelEncoding(data)

    X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
              'Packet Length', 'Packets/Time']]
    y = data['target']

    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y)

    mlp.fit(X_train, y_train)
    predictions = mlp.predict(X_test)
    
    print("Number of Iterations: ", mlp.n_iter_)
    
    from sklearn.metrics import classification_report, confusion_matrix
    print("Confusion Matrix: ", "\n", confusion_matrix(y_test, predictions))
    print("Classification Report: ", "\n", classification_report(y_test, predictions))

    save = input("Save model? ")
    if save == 'y':
        filename = input("Filename for saving?: ")
        pickle.dump(mlp, open(filename, 'wb'))

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

def csv_interval_gather(cap):
    start_time = time.time()
    with open('LiveAnn.csv', 'w', newline='') as csvfile:
        filewriter = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        filewriter.writerow(['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
                             'Packet Length', 'Packets/Time'])

        i = 0
        start = time.time()
        for pkt in cap:
            end = time.time()
            if end - start >= 30:
                break

            try:
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

def main():
    
    # Choose network interface
    cap = int_choice()
    
    # Gather packet information
    packet_info(cap)
    
    # Gather data and write to CSV
    csvgather(cap)
    
    # Train or load the neural network model
    mlp_model = MLP()
    
    # Gather live packet data and write to CSV
    csv_interval_gather(cap)
    
    # Perform live prediction using the trained model
    MLP_Live_predict(cap, mlp_model)


# Define allowed IPs globally
# examples:
allowed_IP = ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']

if __name__ == "__main__":
    main()
