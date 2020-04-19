import pandas as pd
import numpy as np
import csv
from time import perf_counter
from tabulate import tabulate
import matplotlib.pyplot as plt
from joblib import dump, load
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel

from dl85 import DL85Classifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC, SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, Normalizer
from sklearn.decomposition import PCA

from toBoolean import convert

tabulate.WIDE_CHARS_MODE = False

'''
Dictionary of classifiers
'''
def algo_picker(name): 
    switcher = { 
    	"neigh": KNeighborsClassifier(n_neighbors=7,p=1),
    	"gaussian": GaussianNB(),
    	"bernoulli": BernoulliNB(),
        "log": LogisticRegression(C=10, max_iter=1000,random_state=0), 
        "svc": LinearSVC(C=10, max_iter=1000,random_state=0), 
        "tree": DecisionTreeClassifier(max_depth=7,min_samples_split=10,min_samples_leaf=7,random_state=0),
        "forest": RandomForestClassifier(n_estimators=10,max_depth=5,min_samples_leaf=9,random_state=0),
        "gradient": GradientBoostingClassifier(n_estimators=10,max_depth=5,random_state=0),
        "svm": SVC(kernel='poly',C=1000,gamma=100,degree=15,random_state=0),
        "mlp1": MLPClassifier(solver='adam',hidden_layer_sizes=(100, 100, 100),max_iter=10000,random_state=0),
        "mlp2": MLPClassifier(solver='sgd',activation='tanh',alpha=0.1,hidden_layer_sizes=(100,50,50),max_iter=1000,random_state=0),
        "dl8.5": DL85Classifier(max_depth=3, time_limit=120)
    } 
  
    return switcher.get(name, "nothing") 

'''
The idea is the following:
	- We create different situations where we increase the test set size
	- At each step, the K best features are selected (K-set)
	- Starting from step 2, we do the intersection between K-set and the K best features from previous iteration (called Z-set)
	- At each following step, we do a new intersection and replace Z-set by the intersect between Z-set and K-set
'''
def iterative_process(csv, threshold, kind):
	current_set = []
	best_set = []

	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	raw_data = gt[cols]
	raw_target = gt['label']

	# We increase the test size by padd of 15%
	iterations = np.arange(0.15, 1.0, 0.15)
	
	clf = algo_picker(kind)

	for t_size in iterations:

		data_train, data_test, target_train, target_test = train_test_split(raw_data, raw_target, test_size = t_size, random_state = 0)
		
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

		clf.fit(data_train, target_train)

		#Select K best features
		model = SelectFromModel(clf, threshold=threshold, prefit=True)
		train_new = model.transform(data_train)
		mask = model.get_support()
		current_set = data_train.columns[mask]

		#Intersection of two last subsets with the best features
		if t_size != 0.15 :
			best_set = [value for value in current_set if value in best_set]
		else :
			best_set = current_set

	return best_set

'''
Outputs the K best features for 'kind' classifier according to the 'threshold' feature importance
'''
def k_best_features(csv, threshold, kind):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	raw_data = gt[cols]
	raw_target = gt['label']

	clf = algo_picker(kind)

	data_train, data_test, target_train, target_test = train_test_split(raw_data, raw_target, test_size = 0.20, random_state = 0)

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

	clf.fit(data_train, target_train)

	#Select K best features
	model = SelectFromModel(clf, threshold=threshold, prefit=True)
	train_new = model.transform(data_train)
	mask = model.get_support()
	new_current_set = data_train.columns[mask]
	return new_current_set


'''
Process where we select the best features based on the output of the function SelectFromModel from scikit.
Three different plots are displayed :
	- Performances without tuning
	- Performances when only keeping the K best features
	- Performances when applying the iterative process described in iterative_process()
Accuracy/time ratios are also computed and returned 
'''
def feature_selection(csv, kind, threshold=0.005, silent=False):
	cell_text = []
	ratios = [] 

	clf = algo_picker(kind)

	# Classic performances without tuning
	row = []
	start = perf_counter()
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	raw_data = gt[cols]
	raw_target = gt['label']

	data_train, data_test, target_train, target_test = train_test_split(raw_data, raw_target, test_size = 0.20, random_state = 0)

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
	#start = perf_counter()
	clf.fit(data_train, target_train)
	end = perf_counter()
	d_time = end - start
	d_train_acc = clf.score(data_train, target_train)
	d_test_acc = clf.score(data_test, target_test)
	row.append("Classic")
	row.append("119")
	row.append("['f1',...,'f119']")
	row.append(d_train_acc)
	row.append(d_test_acc)
	row.append(d_time)
	row.append(0)
	cell_text.append(row)


	# Performances with K best features selection
	row = []
	ratio = []
	#start = perf_counter()
	fc_start = perf_counter()
	k_best_set = k_best_features(csv, threshold, kind)
	fc_end = perf_counter()

	if len(k_best_set) > 0: #only proceed to feature selection if k_best_feature found some with the requested threshold
		start = perf_counter()
		gt = pd.read_csv(csv)
		data = gt[k_best_set]
		target = gt['label']
		data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

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

		clf.fit(data_train, target_train)
		end = perf_counter()
		k_name = "K best features"
		k_time = end - start
		k_train_acc = clf.score(data_train, target_train)
		k_test_acc = clf.score(data_test, target_test)
		k_values = k_best_set.values

		row.append(k_name)
		row.append(len(k_values))
		row.append(parse_list(k_values))
		row.append(k_train_acc)
		row.append(k_test_acc)
		row.append(k_time)
		row.append(fc_end - fc_start)
		cell_text.append(row)

		if k_test_acc > (d_test_acc - 0.5): #we only accept 5% degradation from the initial test accuracy
			ratio.append(k_name)
			ratio.append(k_values)
			ratio.append(ratio_computation(d_train_acc, k_train_acc, d_time, k_time))
			ratios.append(ratio)
	

	# Performances with features selected from the iterative process
	row = []
	ratio = []
	#start = perf_counter()
	fc_start = perf_counter()
	best_set = iterative_process(csv, threshold, kind)
	fc_end = perf_counter()

	if len(best_set) > 0: #only proceed to feature selection if k_best_feature found some with the requested threshold
		start = perf_counter()
		gt = pd.read_csv(csv)
		data = gt[best_set]
		target = gt['label']
		data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

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

		clf.fit(data_train, target_train)
		end = perf_counter()
		i_name = "Iterative process"
		i_time = end - start
		i_train_acc = clf.score(data_train, target_train)
		i_test_acc = clf.score(data_test, target_test)
		i_values = best_set

		row.append(i_name)
		row.append(len(i_values))
		row.append(parse_list(i_values))
		row.append(i_train_acc)
		row.append(i_test_acc)
		row.append(i_time)
		row.append(fc_end - fc_start)
		cell_text.append(row)

		if i_test_acc > (d_test_acc - 0.5): #we only accept 5% degradation from the initial test accuracy
			ratio.append(i_name)
			ratio.append(i_values)
			ratio.append(ratio_computation(d_train_acc, i_train_acc, d_time, i_time))
			ratios.append(ratio)
	
	if not silent:
		print(tabulate(cell_text, headers = ['Execution','# features','Features selected','Training set acc','Test acc','Time (s)','Fixed cost (s)']))

	return ratios

'''
Launches the feature selection process for different feature importances
Retrieves the best ratios of accuracy/time, sort them and outputs the best result
'''
def fs_driver(csv, kind, thresholds, silent=False):
	ratios = []
	for i in thresholds:
		if not silent:
			print("Threshold : %f" % i)
		ratios += feature_selection(csv, kind, i, silent)
		if not silent:
			print("\n")
	r = range(0,len(ratios))
	k_ratios = [ratios[i] for i in r if ratios[i][0] == "K best features"]
	i_ratios = [ratios[i] for i in r if ratios[i][0] == "Iterative process"]

	k_ratios.sort(key = lambda x: x[2], reverse = True)
	i_ratios.sort(key = lambda x: x[2], reverse = True)

	return [k_ratios[0][1],i_ratios[0][1]]

'''
Compare feature selection performances over time (both with K best feature and iterative process)
'''
def feature_snapshot(csv, kind):
	gt = pd.read_csv(csv)
	thresholds = [0.005,0.01,0.05,0.1,0.2,0.4]
	features = fs_driver(csv, kind, thresholds, True)

	clf = algo_picker(kind)

	# K best
	data_train = gt[features[0]]
	target_train = gt['label']
	clf.fit(data_train, target_train)
	dump(clf,"snapshots/K_best.joblib")

	clf = load("snapshots/K_best.joblib")

	gt = pd.read_csv("../../../dumps/time_analysis/threshold_3/3_20190808_1000.csv")
	data_test = gt[features[0]]
	target_test = gt['label']

	print("K best features : \n")
	print("Accuracy on training set: {:.3f}".format(clf.score(data_train, target_train))) 
	print("Accuracy on test set: {:.3f}".format(clf.score(data_test, target_test)))

	print("------------------------------ \n")

	# Iterative process
	data_train = gt[features[1]]
	target_train = gt['label']
	clf.fit(data_train, target_train)
	dump(clf,"snapshots/iter_proc.joblib")

	clf = load("snapshots/iter_proc.joblib")

	gt = pd.read_csv("../../../dumps/time_analysis/threshold_3/3_20190808_1000.csv")
	data_test = gt[features[1]]
	target_test = gt['label']

	print("Iterative process : \n")
	print("Accuracy on training set: {:.3f}".format(clf.score(data_train, target_train))) 
	print("Accuracy on test set: {:.3f}".format(clf.score(data_test, target_test)))


'''
Used to parse Thomas datasets into new ones that fit our classifiers
'''
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


'''
Uses variance as threshold
//!\\ CAREFUL : PCA with all features doesn't give the same results as not applying since we perform
StandardScaler operation which (most of the time) reduces the accuracy
'''
def PCA_reduction(csv, kind):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	cell_text = []
	clf = algo_picker(kind)

	default_perf = single_perf(csv, kind)
	cell_text.append(['no pca', default_perf[0], default_perf[1], 'all', default_perf[2]])

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	#Fixed cost of parsing the data for PCA, not taken into account for computation time
	scaler = StandardScaler()
	scaler.fit(data_train)
	data_train_raw = scaler.transform(data_train)
	data_test_raw = scaler.transform(data_test)
	for i in [1,0.99,0.95,0.90,0.85]:
	    row = []
	    row.append(i)
	    start = perf_counter()
	    pca = PCA(i) if i != 1 else PCA()
	    pca.fit(data_train_raw)
	    data_train = pca.transform(data_train_raw)
	    data_test = pca.transform(data_test_raw)
	    clf.fit(data_train, target_train)
	    end = perf_counter()
	    row.append(clf.score(data_train, target_train))
	    row.append(clf.score(data_test, target_test))
	    row.append(pca.n_components_)
	    row.append(end-start)
	    cell_text.append(row)
	print(tabulate(cell_text, headers = ['Variance','Training acc','Test acc','Components','Time (s)']))

'''
Uses number of components as threshold
Finds the top 5 PCA combinations offering best time reduction
'''
def PCA_components(csv, kind, silent=False):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	clf = algo_picker(kind)

	default_perf = single_perf(csv, kind)

	data_train_raw, data_test_raw, target_train_raw, target_test_raw = train_test_split(data,target, test_size = 0.20, random_state = 0)

	#Fixed cost of parsing the data for PCA, not taken into account for computation time
	scaler = StandardScaler()
	scaler.fit(data_train_raw)
	data_train_raw = scaler.transform(data_train_raw)
	data_test_raw = scaler.transform(data_test_raw)
	test_accuracy = []
	cell_text = []
	n_comp = range(1,120)
	for i in n_comp:
		timer = []
		start = perf_counter()
		pca = PCA(n_components=i)
		pca.fit(data_train_raw)
		data_train = pca.transform(data_train_raw)
		data_test = pca.transform(data_test_raw)
		clf.fit(data_train, target_train_raw)
		end = perf_counter()
		test_accuracy.append(clf.score(data_test, target_test_raw))
		timer.append(i)
		timer.append(clf.score(data_test, target_test_raw))
		timer.append(end-start)
		cell_text.append(timer)
	better = [c-1 for c in n_comp if cell_text[c-1][2] <= default_perf[2]]
	filtered_cell = [cell_text[x] for x in better]
	filtered_cell.sort(key = lambda x: x[1], reverse = True)
	filtered_cell = filtered_cell[:5]
	filtered_cell.insert(0,['no PCA', default_perf[1], default_perf[2]])

	if not silent:
		plt.plot(n_comp, test_accuracy, label="test accuracy") 
		plt.ylabel("Accuracy")
		plt.xlabel("# components")
		plt.legend()
		plt.axhline(y=default_perf[1], color='g')
		plt.show()
		print("Top 5 features combinations with times <= than default case : \n")
		print(tabulate(filtered_cell, headers = ['# components','Acc','Time']))

	return filtered_cell[1][0]

'''
Performance of PCA over time
'''
def PCA_snapshot(csv, kind, path_to_parent):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data_train = gt[cols]
	target_train = gt['label']

	clf = algo_picker(kind)
	pca = PCA(n_components=PCA_components(csv, kind, False))

	pca.fit(data_train)
	data_train = pca.transform(data_train)
	clf.fit(data_train, target_train)
	dump(clf,"snapshots/PCA.joblib")

	clf = load("snapshots/PCA.joblib")

	gt = pd.read_csv(path_to_parent+"../dumps/time_analysis/threshold_3/3_20190808_1000.csv")
	cols = [col for col in gt.columns if col not in ['label']]
	data_test = gt[cols]
	target_test = gt['label']

	pca.fit(data_test)
	data_test = pca.transform(data_test)


	print("Accuracy on training set: {:.3f}".format(clf.score(data_train, target_train))) 
	print("Accuracy on test set: {:.3f}".format(clf.score(data_test, target_test)))

'''
Outputs [training accuracy, test accuracy, time] for a classifier over a specifid dataset
'''
def single_perf(csv, kind):
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	target = gt['label']

	clf = algo_picker(kind)

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	if kind != "tree" and kind != "forest" and kind != "gradient":
		if kind == "gaussian" or kind == "bernoulli":
			scaler = StandardScaler()
		else:
			scaler = Normalizer()
		scaler.fit(data_train)
		data_train = scaler.transform(data_train)
		data_test = scaler.transform(data_test)

	g_start = perf_counter()
	clf.fit(data_train, target_train)
	g_end = perf_counter()
	g_time = g_end - g_start
	return [clf.score(data_train, target_train), clf.score(data_test, target_test), g_time]


'''
Prints performances for a classifier ober a specific dataset
Allows to use boolean dataset
'''
def perf(csv, kind, only_b):
	second_test = False
	gt = pd.read_csv(csv)
	cols = [col for col in gt.columns if col not in ['label']]
	data = gt[cols]
	if only_b:
		data = convert(data, False)
		second_test = True
	target = gt['label']

	clf = algo_picker(kind)

	data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

	if kind != "tree" and kind != "forest" and kind != "gradient":
		if kind == "gaussian" or kind == "bernoulli":
			scaler = StandardScaler()
		else:
			scaler = Normalizer()
		scaler.fit(data_train)
		data_train = scaler.transform(data_train)
		data_test = scaler.transform(data_test)

	clf.fit(data_train, target_train)
	print("Most important : \n")
	print("Accuracy on training set: {:.3f}".format(clf.score(data_train, target_train))) 
	print("Accuracy on test set: {:.3f}".format(clf.score(data_test, target_test)))

	if second_test:
		gt = pd.read_csv(csv)
		cols = [col for col in gt.columns if col not in ['label']]
		data = gt[cols]
		if only_b:
			data = convert(data, True)
		target = gt['label']

		clf = algo_picker(kind)

		data_train, data_test, target_train, target_test = train_test_split(data,target, test_size = 0.20, random_state = 0)

		if kind != "tree" and kind != "forest" and kind != "gradient":
			if kind == "gaussian" or kind == "bernoulli":
				scaler = StandardScaler()
			else:
				scaler = Normalizer()
			scaler.fit(data_train)
			data_train = scaler.transform(data_train)
			data_test = scaler.transform(data_test)

		clf.fit(data_train, target_train)
		print("---------------\n")
		print("All features : \n")
		print("Accuracy on training set: {:.3f}".format(clf.score(data_train, target_train))) 
		print("Accuracy on test set: {:.3f}".format(clf.score(data_test, target_test)))

'''
Performs time comparison for a specifid classifier
All thresholds and dataset size are tested
'''
def time_comparison(kind, path_to_parent):
	clf = algo_picker(kind)
	file_path = "_20190615_"
	csv_path = path_to_parent+"../dumps/time_analysis/threshold_"
	snap_path = "snapshots/"
	size = ["6000","14000","21000","31000"]
	thresholds = ["1","2","3","4","5"]
	for t in thresholds:
		print("Acceptation threshold : %s/5 \n" % t)
		cell_text = []
		for i in size:
			row = []
			row.append(i)
			row.append(float(i)/7000)

			folder = csv_path+t+"/"
			file = t+file_path+i+".csv"
			csv_file = folder+file
			gt = pd.read_csv(csv_file)
			cols = [col for col in gt.columns if col not in ['label']]
			data_train = gt[cols]
			target_train = gt['label']

			if kind != "tree" and kind != "forest" and kind != "gradient":
				if kind == "gaussian" or kind == "bernoulli":
					scaler = StandardScaler()
				else:
					scaler = Normalizer()
				scaler.fit(data_train)
				data_train = scaler.transform(data_train)

			clf.fit(data_train, target_train)

			snap_file = snap_path+kind+"_"+t+file_path+i+".joblib"
			dump(clf,snap_file)
			clf = load(snap_file)

			gt = pd.read_csv(folder+t+"_20190808_1000.csv")
			cols = [col for col in gt.columns if col not in ['label']]
			data_test = gt[cols]
			target_test = gt['label']

			if kind != "tree" and kind != "forest" and kind != "gradient":
				data_test = scaler.transform(data_test)

			row.append(clf.score(data_train, target_train))
			row.append(clf.score(data_test, target_test))
			cell_text.append(row)
		print(tabulate(cell_text, headers = ['# malwares in training set','Approx. period in weeks','Training acc','Test acc']))


'''
Compute the accuracy/time ratio, i.e. for a loss of 1% precision, how much time do I save
'''
def ratio_computation(from_acc, to_acc, from_time, to_time):
	diff_acc = (to_acc - from_acc) / from_acc
	diff_time = (to_time - from_time) / from_time
	if diff_acc != 0:
		ratio = (diff_time / diff_acc)
	else:
		ratio = diff_time
	return ratio

'''
Split a list of features in multiple lines to enhance the display when printed
'''
def parse_list(features):
	link = "["
	for i in range(0,len(features)):
		if i % 3 == 0 and i != 0:
			link += "\n"
		link += "'"+str(features[i])+"',"
	return link[:-1]+"]"


if __name__ == '__main__':
	pass

