import argparse
import textwrap
import pandas as pd
from tabulate import tabulate
from sklearn.model_selection import cross_val_score 
from sklearn.datasets import load_iris
from sklearn.neighbors import KNeighborsClassifier
from sklearn.naive_bayes import GaussianNB, MultinomialNB, BernoulliNB
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC, SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier


from utils import algo_picker

def cross_validation(classifier, csv):
    gt = pd.read_csv(csv)
    cols = [col for col in gt.columns if col not in ['label']]
    data = gt[cols]
    target = gt['label']
    cell_text = []
    for c in classifier:
        row = []
        clf = algo_picker(c)
        scores = cross_val_score(clf, data, target, cv=5)
        row.append(c)
        row.append(scores)
        row.append(scores.mean())
        cell_text.append(row)
    print(tabulate(cell_text, headers = ['Classifier','Scores','Mean']))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c", 
                        "--classifier",
                        nargs="+",
                        help=textwrap.dedent('''\
                            Array of desired classifiers like
                            [tree, gaussian, neigh, mlp1, svc]
                            '''))
    parser.add_argument("-g",
                        "--groundtruth",
                        type=str,
                        help="Path to ground truth csv")
    args = parser.parse_args()
    classifiers = args.classifier if args.classifier != None else ['neigh','tree','forest','gradient']
    csv = args.groundtruth if args.groundtruth != None else "../../dumps/various_sizes/8K.csv"
    cross_validation(classifiers, csv)