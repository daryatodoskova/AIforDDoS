import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
import matplotlib.pyplot as plt
import numpy as np
import pickle
import glob

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

# def LabelEncoding(data):
#     # Encode categorical variables using LabelEncoder
#     columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
#     le = LabelEncoder()
#     for feature in columnsToEncode:
#         try:
#             data[feature] = le.fit_transform(data[feature])
#         except:
#             print('Error: ' + feature)
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
    # Load dataset
    #data = final_01_df

    # Preprocess dataset
    # data = preprocess_data(data)

    # Encode categorical variables
    # data = LabelEncoding(data)

    # Split features and target variable
    # X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Destination IP', 'Source Port', 'Dest Port',
    #           'Packet Length', 'Packets/Time']]
    # y = data['target']

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
                        verbose=True)

    # Train MLP model
    mlp.fit(X_train, y_train)
    
    # Make predictions on test set
    predictions = mlp.predict(X_test)
    
    # Evaluate model performance
    print("Number of Iterations: ", mlp.n_iter_)
    visualize_confusion_matrix(y_test, predictions)
    print("Classification Report: ", "\n", classification_report(y_test, predictions))

    # Optionally save the trained model
    # save = input("Save model? (y/n): ")
    # if save.lower() == 'y':
    #     filename = input("Filename for saving?: ")
    #     pickle.dump(mlp, open(filename, 'wb'))

if __name__ == "__main__":
    MLP()
