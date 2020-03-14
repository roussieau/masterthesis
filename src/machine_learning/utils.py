import pandas as pd
import numpy as np
import csv
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel

from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC, SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier


def feature_selection(csv, padd, kind):

	features_sets = []
	basic_stats_tr = []
	basic_stats_te = []
	transform_stats_tr = []
	transform_stats_te = []
	previous_stats_tr = []
	previous_stats_te = []

	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	raw_data = gt[cols]
	raw_target = gt['label']

	iterations = np.arange(padd,1.0,padd)

	def show_plot(iterations,training,test,title):
		plt.title(title)		
		plt.plot(iterations, training, label="training accuracy") 
		plt.plot(iterations, test, label="test accuracy") 
		plt.ylabel("Accuracy")
		plt.xlabel("Training size")
		plt.legend()
		plt.show()

	def algo_picker(name): 
	    switcher = { 
	        "log": LogisticRegression(C=1, max_iter=10000,random_state=0), 
	        "svc": LinearSVC(C=0.1, max_iter=10000,random_state=0), 
	        "tree": DecisionTreeClassifier(max_depth=4,min_samples_split=0.1,min_samples_leaf=10,random_state=0),
	        "forest": RandomForestClassifier(n_estimators=10,max_depth=10,min_samples_leaf=5,random_state=0),
	        "gradient": GradientBoostingClassifier(n_estimators=10,max_depth=10,min_samples_leaf=5,random_state=0),
	        "mlp": MLPClassifier(solver='adam',activation='tanh',alpha=100,hidden_layer_sizes=(50, 50, 100)),
	    } 
	  
	    return switcher.get(name, "nothing") 


	logreg = algo_picker(kind)


	for t_size in iterations:
		print(t_size)

		#Computing initial accuracies without tuning
		data_train, data_test, target_train, target_test = train_test_split(raw_data, raw_target, test_size = 1-t_size, random_state = 0)
		print(data_train.shape)
		logreg.fit(data_train, target_train)
		basic_stats_tr.append(logreg.score(data_train, target_train))
		basic_stats_te.append(logreg.score(data_test, target_test))

		#Select best features
		model = SelectFromModel(logreg, prefit=True)
		train_new = model.transform(data_train)
		print(train_new.shape)
		mask = model.get_support()
		new_current_set = data_train.columns[mask]
		features_sets.append(new_current_set)

		#Creating new dataset with only newly-found best features and computing new accuracies
		gt = pd.read_csv(csv)
		data = gt[new_current_set]
		target = gt['label']
		data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 1-t_size, random_state = 0)
		logreg.fit(data_train, target_train)
		transform_stats_tr.append(logreg.score(data_train, target_train))
		transform_stats_te.append(logreg.score(data_test, target_test))

		#Creating new dataset with previous best features and computing new accuracies
		if t_size != padd :
			gt = pd.read_csv(csv)
			previous_set = features_sets[-2]
			data = gt[previous_set]
			target = gt['label']
			data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 1-t_size, random_state = 0)
			logreg.fit(data_train, target_train)
			previous_stats_tr.append(logreg.score(data_train, target_train))
			previous_stats_te.append(logreg.score(data_test, target_test))

			#Intersection of two last subsets with the best features
			next_set = [value for value in new_current_set if value in previous_set]
			features_sets.append(next_set)
			print(len(next_set))


	show_plot(iterations,basic_stats_tr, basic_stats_te,"Classic - without tuning")
	print("Training max value : %s" % max(basic_stats_tr))
	print("Test max value : %s" % max(basic_stats_te))
	show_plot(iterations,transform_stats_tr,transform_stats_te,"After feature selection")
	print("Training max value : %s" % max(transform_stats_tr))
	print("Test max value : %s" % max(transform_stats_te))
	show_plot(iterations[1:],previous_stats_tr,previous_stats_te,"After previous feature selection")
	print("Training max value : %s" % max(previous_stats_tr))
	print("Test max value : %s" % max(previous_stats_te))

def thomas_parser(csv_path):
	data = []
	data_filter = []
	target = []
	target_filter = []
	packers = []
	packed_num = 1
	with open(csv_path+'.csv', newline='') as csvfile:
		darray = list(csv.reader(csvfile))
	for row in darray:
		if len(row) == 121:
			data_filter.append(row[1:-1])
			label = row[-1]
			if label == "not packed":
				target_filter.append(0)
			else:
				if label in packers :
					target_filter.append(packers.index(label)+1)
				else :
					packers.append(label)
					target_filter.append(packed_num)
					packed_num+=1

	data = np.array(data_filter)
	df1 = pd.DataFrame(data=data[0:,0:],
	                    index=[i for i in range(data.shape[0])],
	                    columns=['f'+str(i) for i in range(data.shape[1])])
	target = np.array(target_filter)
	df2 = pd.DataFrame({'label':target})
	df = df1.join(df2)
	file_name = csv_path+"_thomas.csv"
	df.to_csv(file_name,index=False)
	return file_name



