import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix

def MLP():
    l_data = input("Name of CSV file? ")
    
    data = pd.read_csv(l_data, delimiter=',')
    data = LabelEncoding(data)

    X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port',
              'Packet Length', 'Packets/Time']]
    y = data['target']

    X_train, X_test, y_train, y_test = train_test_split(X, y)

    mlp = MLPClassifier(hidden_layer_sizes=(100, 100), activation='logistic', max_iter=1000, verbose=True,
                        tol=0.00000001, early_stopping=True, shuffle=True)

    mlp.fit(X_train, y_train)
    predictions = mlp.predict(X_test)
    
    print("Number of Iterations: ", mlp.n_iter_)
    
    print("Confusion Matrix: ", "\n", confusion_matrix(y_test, predictions))
    print("Classification Report: ", "\n", classification_report(y_test, predictions))

    save = input("Save model? ")
    if save == 'y':
        filename = input("Filename for saving?: ")
        pickle.dump(mlp, open(filename, 'wb'))

def LabelEncoding(data):
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))
    le = LabelEncoder()
    for feature in columnsToEncode:
        try:
            data[feature] = le.fit_transform(data[feature])
        except:
            print('Error: ' + feature)
    return data

if __name__ == "__main__":
    MLP()
