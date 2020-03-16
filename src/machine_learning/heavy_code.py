import pandas as pd
import numpy as np
import csv
import time
from tabulate import tabulate
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import roc_curve, auc
from sklearn.model_selection import GridSearchCV, RandomizedSearchCV

from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC, SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, Normalizer
from sklearn.decomposition import PCA

from utils import PCA_reduction


def decision_tree():
	gt = pd.read_csv('../dumps/2020.02.10-12.14.csv')
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']
	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	f = open("decision_tree.txt","w")

	parameters = {'max_depth': np.arange(1,11), 'min_samples_split': np.arange(1,21), 'min_samples_leaf': np.arange(1,11), 'max_features': np.arange(1,120)}
	clf = GridSearchCV(DecisionTreeClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("GSCV")
	f.write('\n')
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	parameters = {'max_depth': np.arange(1,11), 'min_samples_split': np.arange(1,21), 'min_samples_leaf': np.arange(1,11), 'max_features': np.arange(1,120)}
	clf = RandomizedSearchCV(DecisionTreeClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("RSCV")
	f.write('\n')
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	f.close()

def random_forest():
	f = open("random_forest.txt","w")

	#max features
	gt = pd.read_csv('../dumps/2020.02.10-12.14.csv')
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	training_accuracy = [] 
	test_accuracy = []
	settings = range(1, 120)
	for f in settings:
	    clf = RandomForestClassifier(max_features=f, n_jobs=-1)
	    clf.fit(data_train, target_train)
	    training_accuracy.append(clf.score(data_train, target_train))
	    test_accuracy.append(clf.score(data_test, target_test))
	f.write("max features \n")
	f.write(training_accuracy)
	f.write('\n')
	f.write(test_accuracy)
	f.write('\n')

	#best match
	parameters = {'n_estimators': np.arange(1,21), 'max_depth': np.arange(1,21), 'min_samples_split': np.arange(1,11), 'min_samples_leaf': np.arange(1,11), 'max_features': np.arange(1,120)}
	clf = GridSearchCV(RandomForestClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("GSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	parameters = {'n_estimators': np.arange(1,21), 'max_depth': np.arange(1,21), 'min_samples_split': np.arange(1,11), 'min_samples_leaf': np.arange(1,11), 'max_features': np.arange(1,120)}
	clf = RandomizedSearchCV(RandomForestClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("RSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	f.close()

def gradient_boosted():
	f = open("gradient_boosted.txt","w")

	gt = pd.read_csv('../dumps/2020.02.10-12.14.csv')
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	parameters = {'n_estimators': np.arange(1,21), 'max_depth': np.arange(1,21), 'min_samples_split': np.arange(1,11), 'min_samples_leaf': np.arange(1,11), 'max_features': np.arange(1,120), 'learning_rate':[0.01,0.1,0.25,0.5,1.0]}
	clf = GridSearchCV(GradientBoostingClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("GSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)

	parameters = {'n_estimators': np.arange(1,21), 'max_depth': np.arange(1,21), 'min_samples_split': np.arange(1,11), 'min_samples_leaf': np.arange(1,11), 'max_features': np.arange(1,120), 'learning_rate':[0.01,0.1,0.25,0.5,1.0]}
	clf = GridSearchCV(GradientBoostingClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("RSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	f.close()

def knn():
	f = open("KNN.txt","w")

	gt = pd.read_csv('../dumps/2020.02.10-12.14.csv')
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']
	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)
	scaler = Normalizer()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	parameters = {'n_neighbors': np.arange(1,11), 'p':[1,2,3,4,5]}
	clf = GridSearchCV(KNeighborsClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("GSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	parameters = {'n_neighbors': np.arange(1,11), 'p':[1,2,3,4,5]}
	clf = RandomizedSearchCV(KNeighborsClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("RSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	f.close()

def neural_network():
	f = open("neural.txt","w")

	gt = pd.read_csv('../dumps/2020.02.10-12.14.csv')
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']
	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	parameters = {'solver': ['lbfgs','sgd','adam'], 'max_iter': [1000,10000], 'alpha': [0.0001,0.001,0.1,1,10,100], 'hidden_layer_sizes':[(50,50,50), (100,100,100), (50,100,50), (100,50,50), (50,50,100), (100,)], 'activation':['identity','logistic', 'tanh', 'relu']}
	clf = GridSearchCV(MLPClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("GSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	parameters = {'solver': ['lbfgs','sgd','adam'], 'max_iter': [1000,10000], 'alpha': [0.0001,0.001,0.1,1,10,100], 'hidden_layer_sizes':[(50,50,50), (100,100,100), (50,100,50), (100,50,50), (50,50,100), (100,)], 'activation':['identity','logistic', 'tanh', 'relu']}
	clf = RandomizedSearchCV(MLPClassifier(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("RSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	f.close()

def svm():
	f = open("svm.txt","w")

	gt = pd.read_csv('../dumps/2020.02.10-12.14.csv')
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']
	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)
	scaler = Normalizer()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	#best match
	parameters = {'kernel': ['rbf','poly'], 'gamma' : [0.1,1,10,100,1000], 'C': [0.1,1,10,100,1000]}
	clf = GridSearchCV(SVC(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("GSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	parameters = {'kernel': ['rbf','poly'], 'gamma' : [0.1,1,10,100,1000], 'C': [0.1,1,10,100,1000]}
	clf = RandomizedSearchCV(SVC(), parameters, n_jobs=-1)
	clf.fit(data_train, target_train)
	f.write("RSCV \n")
	f.write(clf.score(data_train, target_train))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')
	f.write(clf.score(data_test, target_test))
	f.write('\n')
	f.write(clf.best_params_)
	f.write('\n')

	#thomas datasets
	gt = pd.read_csv("../dumps/2019-08.Merged_thomas.csv")
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)
	scaler = Normalizer()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	tree = SVC(kernel='poly',C=0.1,gamma=100,degree=3, n_jobs=-1)
	tree.fit(data_train, target_train)
	f.write("Thomas DS 2019-08 \n")
	f.write("Accuracy on training set: {:.3f}".format(tree.score(data_train, target_train)))
	f.write('\n')
	f.write("Accuracy on test set: {:.3f}".format(tree.score(data_test, target_test)))
	f.write('\n')

	gt = pd.read_csv("../dumps/2019-09.Merged_thomas.csv")
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)
	scaler = Normalizer()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	tree = SVC(kernel='poly',C=1000, n_jobs=-1)
	tree.fit(data_train, target_train)
	f.write("Thomas DS 2019-09 \n")
	f.write("Accuracy on training set: {:.3f}".format(tree.score(data_train, target_train)))
	f.write('\n')
	f.write("Accuracy on test set: {:.3f}".format(tree.score(data_test, target_test)))
	f.write('\n')

	f.close()

if __name__ == "__main__":
	print("hllo")