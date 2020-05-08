import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.feature_selection import SelectFromModel
from sklearn.preprocessing import StandardScaler, Normalizer


def display_plot_logreg(csv, t_size, min_c, max_c):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = t_size, random_state = 0)
	scaler = StandardScaler()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	training_accuracy = [] 
	test_accuracy = []
	logreg_settings = []
	start_point = min_c
	while start_point <= max_c:
	    clf = LogisticRegression(C=start_point, max_iter=100000) 
	    clf.fit(data_train, target_train)
	    training_accuracy.append(clf.score(data_train, target_train))
	    test_accuracy.append(clf.score(data_test, target_test))
	    logreg_settings.append(start_point)
	    start_point *= 10
	plt.plot(range(len(logreg_settings)), training_accuracy, label="training accuracy")
	plt.plot(range(len(logreg_settings)), test_accuracy, label="test accuracy")
	plt.xticks(range(len(logreg_settings)),logreg_settings)
	plt.ylabel("Accuracy")
	plt.xlabel("C value")
	plt.legend()

def display_plot_svc(csv, t_size, min_c, max_c):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = t_size, random_state = 0)
	scaler = StandardScaler()
	scaler.fit(data_train)
	data_train = scaler.transform(data_train)
	data_test = scaler.transform(data_test)

	training_accuracy = [] 
	test_accuracy = []
	svc_settings = []
	start_point = min_c
	while start_point <= max_c:
	    clf = LinearSVC(C=start_point, max_iter=100000) 
	    clf.fit(data_train, target_train)
	    training_accuracy.append(clf.score(data_train, target_train))
	    test_accuracy.append(clf.score(data_test, target_test))
	    svc_settings.append(start_point)
	    start_point *= 10
	plt.plot(range(len(logreg_settings)), training_accuracy, label="training accuracy")
	plt.plot(range(len(logreg_settings)), test_accuracy, label="test accuracy")
	plt.xticks(range(len(logreg_settings)),logreg_settings)
	plt.ylabel("Accuracy")
	plt.xlabel("C value")
	plt.legend()

