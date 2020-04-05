import sys
import argparse
import time
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler, Normalizer


def display_plot(csv, t_size, max_neigh):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = t_size, random_state = 0)

	scaler = Normalizer()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	training_accuracy = [] 
	test_accuracy = []
	neighbors_settings = range(1, max_neigh)
	for n_neighbors in neighbors_settings:
	    clf = KNeighborsClassifier(n_neighbors=n_neighbors) 
	    clf.fit(data_train, target_train)
	    training_accuracy.append(clf.score(data_train, target_train))
	    test_accuracy.append(clf.score(data_test, target_test))
	plt.plot(neighbors_settings, training_accuracy, label="training accuracy") 
	plt.plot(neighbors_settings, test_accuracy, label="test accuracy") 
	plt.ylabel("Accuracy")
	plt.xlabel("n_neighbors")
	plt.legend()

def sober_results(csv, t_size, neigh):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = t_size, random_state = 0)
	scaler = StandardScaler()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	clf = KNeighborsClassifier(n_neighbors=neigh)
	clf.fit(data_train, target_train)
	print("Training set accuracy: {:.2f}".format(clf.score(data_train, target_train)))
	print("Test set accuracy: {:.2f}".format(clf.score(data_test, target_test)))
