import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np
import pickle
import glob

# !wget http://205.174.165.80/CICDataset/CICDDoS2019/Dataset/CSVs/CSV-03-11.zip
# !unzip CSV-03-11.zip

datasets_dic = {}
count = 0

path = r'./03-11'
all_files = glob.glob(path + "/*.csv")
all_files

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

attack_sample_df_dic = {}
labels = label_df['index']
attack_df = initial_df[ initial_df[' Label'] != 'BENIGN' ]
for label in labels:
  attack_sample_df_dic[label] = attack_df[attack_df[' Label'] == label][:300]

attack_sample_df = pd.concat(attack_sample_df_dic)
# 10% attacks vs 90% benign
BENIGN_sample_df = initial_df[initial_df[' Label'] == 'BENIGN'][:18900]


def preprocess_data(data):
    # Check for NaN values and drop rows containing NaN
    data = data.dropna()

    # Check for infinity values and replace them with a large finite value
    data = data.replace([np.inf, -np.inf], np.finfo(np.float64).max)

    # Normalize numerical features
    scaler = StandardScaler()
    data[['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time']] = scaler.fit_transform(data[['Source Port', 'Dest Port', 'Packet Length', 'Packets/Time']])
    
    return data

def LabelEncoding(data):
    # Encode categorical variables using LabelEncoder
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
    le = LabelEncoder()
    for feature in columnsToEncode:
        try:
            data[feature] = le.fit_transform(data[feature])
        except:
            print('Error: ' + feature)
    return data

def MLP():
    # Load dataset
    data = initial_df

    # Preprocess dataset
    data = preprocess_data(data)

    # Encode categorical variables
    data = LabelEncoding(data)

    # Split features and target variable
    X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Destination IP', 'Source Port', 'Dest Port',
              'Packet Length', 'Packets/Time']]
    y = data['target']

    # Split dataset into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y)

    # Initialize MLP classifier
    mlp = MLPClassifier(hidden_layer_sizes=(100, 100), activation='relu', solver='sgd', max_iter=1000, alpha=0.0001, batch_size='auto', verbose=True)

    # Train MLP model
    mlp.fit(X_train, y_train)
    
    # Make predictions on test set
    predictions = mlp.predict(X_test)
    
    # Evaluate model performance
    print("Number of Iterations: ", mlp.n_iter_)
    print("Confusion Matrix: ", "\n", confusion_matrix(y_test, predictions))
    print("Classification Report: ", "\n", classification_report(y_test, predictions))

    # Optionally save the trained model
    save = input("Save model? (y/n): ")
    if save.lower() == 'y':
        filename = input("Filename for saving?: ")
        pickle.dump(mlp, open(filename, 'wb'))

if __name__ == "__main__":
    MLP()
