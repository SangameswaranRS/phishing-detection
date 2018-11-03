import arff
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split


def train_and_export_model():
    print('[INFO] Loading Dataset ')
    dataset = arff.load(open('dataset.arff', 'r'))
    data = np.array(dataset['data'])
    print('[INFO] Load Complete')
    data = data[:, [0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 22, 30]]
    for feature in dataset['attributes']:
        print('      [.]' + str(feature[0]))
    x, y = data[:, :-1], data[:, -1]
    print('[INFO] Splitting into training and testing datasets')
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.3)
    print('[INFO] Training Classifier')
    clf = RandomForestClassifier(n_estimators=20)
    clf.fit(x_train, y_train)
    accuracy = clf.score(x_test, y_test)
    print('[INFO] Training Done')
    print("[INFO] Training Accuracy: " + str(accuracy))
    return clf
