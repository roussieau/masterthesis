import pandas as pd
import numpy as np
import csv
import time
from tabulate import tabulate
import matplotlib.pyplot as plt
from joblib import dump, load
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel

from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC, SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, Normalizer
from sklearn.decomposition import PCA

from toBoolean import convert, convert_only_bool


def algo_picker(name): 
    switcher = { 
    	"neigh": KNeighborsClassifier(n_neighbors=6,p=1),
    	"gaussian": GaussianNB(),
    	"bernoulli": BernoulliNB(),
        "log": LogisticRegression(C=0.01, max_iter=100,random_state=0), 
        "svc": LinearSVC(C=0.01, max_iter=10000,random_state=0), 
        "tree": DecisionTreeClassifier(max_depth=4,min_samples_split=0.1,min_samples_leaf=10,random_state=0),
        "forest": RandomForestClassifier(n_estimators=10,max_depth=10,min_samples_leaf=5,random_state=0),
        "gradient": GradientBoostingClassifier(n_estimators=10,max_depth=10,min_samples_leaf=5,random_state=0),
        "svm": SVC(kernel='poly',C=0.1,gamma=100,degree=3),
        "mlp1": MLPClassifier(solver='adam',activation='tanh',alpha=100,hidden_layer_sizes=(50, 50, 100)),
        "mlp2": MLPClassifier(solver='sgd',activation='tanh',alpha=0.1,hidden_layer_sizes=(100,50,50),max_iter=1000)
    } 
  
    return switcher.get(name, "nothing") 


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

	
	logreg = algo_picker(kind)


	for t_size in iterations:
		print(t_size)

		#Computing initial accuracies without tuning
		data_train, data_test, target_train, target_test = train_test_split(raw_data, raw_target, test_size = 1-t_size, random_state = 0)
		if(kind == "log" or kind == "svc"):
			scaler = Normalizer()
			scaler.fit(data_train)
			data_train = scaler.transform(data_train)
			data_test = scaler.transform(data_test)
			data_train = pd.DataFrame(data=data_train[0:,0:],
				                    index=[i for i in range(data_train.shape[0])],
				                    columns=['f'+str(i) for i in range(data_train.shape[1])])
			data_test = pd.DataFrame(data=data_test[0:,0:],
				                    index=[i for i in range(data_test.shape[0])],
				                    columns=['f'+str(i) for i in range(data_test.shape[1])])
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
		if(kind == "log" or kind == "svc"):
			scaler = Normalizer()
			scaler.fit(data_train)
			data_train = scaler.transform(data_train)
			data_test = scaler.transform(data_test)
			data_train = pd.DataFrame(data=data_train[0:,0:],
				                    index=[i for i in range(data_train.shape[0])],
				                    columns=['f'+str(i) for i in range(data_train.shape[1])])
			data_test = pd.DataFrame(data=data_test[0:,0:],
				                    index=[i for i in range(data_test.shape[0])],
				                    columns=['f'+str(i) for i in range(data_test.shape[1])])
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
			if(kind == "log" or kind == "svc"):
				scaler = Normalizer()
				scaler.fit(data_train)
				data_train = scaler.transform(data_train)
				data_test = scaler.transform(data_test)
				data_train = pd.DataFrame(data=data_train[0:,0:],
					                    index=[i for i in range(data_train.shape[0])],
					                    columns=['f'+str(i) for i in range(data_train.shape[1])])
				data_test = pd.DataFrame(data=data_test[0:,0:],
					                    index=[i for i in range(data_test.shape[0])],
					                    columns=['f'+str(i) for i in range(data_test.shape[1])])
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
	                    columns=['f'+str(i+1) for i in range(data.shape[1])])
	target = np.array(target_filter)
	df2 = pd.DataFrame({'label':target})
	df = df1.join(df2)
	file_name = csv_path+"_thomas.csv"
	df.to_csv(file_name,index=False)
	return file_name

def PCA_reduction(csv, kind):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	clf = algo_picker(kind)

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)
	scaler = StandardScaler()
	scaler.fit(data_train)
	data_train_raw = scaler.transform(data_train)
	data_test_raw = scaler.transform(data_test)
	cell_text = []
	for i in [1,0.99,0.95,0.90,0.85]:
	    row = []
	    row.append(i)
	    start = time.time()
	    pca = PCA(i) if i != 1 else PCA()
	    pca.fit(data_train_raw)
	    data_train = pca.transform(data_train_raw)
	    data_test = pca.transform(data_test_raw)
	    clf.fit(data_train, target_train)
	    end = time.time()
	    row.append(clf.score(data_train, target_train))
	    row.append(clf.score(data_test, target_test))
	    row.append(pca.n_components_)
	    row.append(end-start)
	    cell_text.append(row)
	print(tabulate(cell_text, headers = ['Variance','Training acc','Test acc','Components','Time (s)']))

def perf(csv, kind, only_b):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	if only_b:
		data = convert(data)
	target = gt['label']

	clf = algo_picker(kind)

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	if kind != "tree" and kind != "forest" and kind != "gradient":
		scaler = Normalizer()
		scaler.fit(data_train)
		data_train = scaler.transform(data_train)
		data_test = scaler.transform(data_test)

	clf.fit(data_train, target_train)
	print("Accuracy on training set: {:.3f}".format(clf.score(data_train, target_train))) 
	print("Accuracy on test set: {:.3f}".format(clf.score(data_test, target_test)))

def time_comparison(kind):
	clf = algo_picker(kind)
	file_path = "default_20190615_"
	csv_path = "../dumps/"
	snap_path = "snapshots/"
	csv = ["6000","14000","21000","31000"]
	cell_text = []
	for i in csv:
		row = []
		row.append(i)
		row.append(float(i)/7000)

		gt = pd.read_csv(csv_path+file_path+i+".csv")
		cols = [col for col in gt.columns if col not in ['label']]
		data_train = gt[cols]
		target_train = gt['label']

		if kind != "tree" and kind != "forest" and kind != "gradient":
			scaler = Normalizer()
			scaler.fit(data_train)
			data_train = scaler.transform(data_train)

		clf.fit(data_train, target_train)

		dump(clf,"snapshots/tree_default_20190615_6000.joblib")
		dump(clf,snap_path+kind+"_"+file_path+i+".joblib")
		clf = load(snap_path+kind+"_"+file_path+i+".joblib")

		gt = pd.read_csv("../dumps/default_20190808_1000.csv")
		cols = [col for col in gt.columns if col not in ['label']]
		data_test = gt[cols]
		target_test = gt['label']

		if kind != "tree" and kind != "forest" and kind != "gradient":
			data_test = scaler.transform(data_test)

		row.append(clf.score(data_train, target_train))
		row.append(clf.score(data_test, target_test))
		cell_text.append(row)
	print(tabulate(cell_text, headers = ['# malwares in training set','Approx. period in weeks','Training acc','Test acc']))

if __name__ == '__main__':
	pass

