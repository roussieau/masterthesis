#!/usr/bin/env python3

import sys
import argparse
import textwrap
import random
import pandas as pd
from tabulate import tabulate
from joblib import dump, load


def path_picker(name, threshold):
	base = '../machine_learning/'
	switcher = { 
		'neigh': 'KNearestNeighbors/',
		'gaussian': 'NaiveBayes/',
		'bernoulli': 'NaiveBayes/',
		'log': 'LinearModels/LogisticRegression/', 
		'svc': 'LinearModels/SVC/', 
		'tree': 'Trees/decision_trees/',
		'forest': 'Trees/random_forests/',
		'gradient': 'Trees/gradient_boosting/',
		'svm': 'SVM/',
		'mlp1': 'NeuralNetworks/',
		'mlp2': 'NeuralNetworks/',
		'dl8.5': 'Trees/dl8.5/'
	}
	clf = switcher.get(name, 'nothing')
	if clf == 'nothing':
		print('No classifier found')
		sys.exit()
	return base +  clf + 'snapshots/' + name + '_' + str(threshold) + '_20190615_31000.joblib'


def verify(threshold, repetition, classifiers):
	csv = '../dumps/time_analysis/threshold_' + str(threshold) + '/' + str(threshold) + '_20190615_31000.csv'
	df = pd.read_csv(csv)
	ceil = df.shape[0]
	for c in classifiers:
		cell_text = []
		correct = 0
		clf = load(path_picker(c,threshold))
		for i in range(0,repetition):
			row = []
			index = random.randint(2,ceil)
			line = df.iloc[index]
			cols = [col for col in df.columns if col not in ['label']]
			x = [line[cols]]
			y = line['label']
			row.append(c)
			row.append(index)
			row.append(y)
			predict_y = clf.predict(x)
			row.append(predict_y)
			if y == predict_y:
				correct += 1
				row.append('MATCH')
			else:
				row.append('ERROR')
			cell_text.append(row)
		print(tabulate(cell_text, headers = ['Classifier','Row index','Y','Predicted Y','Status']))
		print("Accuracy : %d %s" % (((correct/repetition)*100),'%'))



if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-t",
                        "--threshold",
                        type=int,
                        help="Threshold for ground truth generation (max. 5)",
                        default=3)
    parser.add_argument("-r",
                        "--repetition",
                        type=int,
                        help="Number of tests",
                        default=10)
    parser.add_argument("-c", 
    					"--classifier",
                        nargs="+",
                        help=textwrap.dedent('''\
                            Array of desired classifiers like
                            [tree, gaussian, neigh, mlp1, svc]
                            '''))
    args = parser.parse_args()
    classifiers = args.classifier if args.classifier != None else ['tree']
    verify(args.threshold, args.repetition, classifiers)