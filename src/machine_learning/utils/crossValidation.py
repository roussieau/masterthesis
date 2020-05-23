import argparse
import textwrap
import pandas as pd
from tabulate import tabulate
from sklearn import preprocessing
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, Normalizer
from sklearn.decomposition import PCA

from utils import algo_picker, fs_driver
from toBoolean import convert

def preprocess(kind, csv):
    clf = algo_picker(kind)

    gt = pd.read_csv(csv)
    cols = [col for col in gt.columns if col not in ['label']]
    data = gt[cols]
    target = gt['label']
    if kind == "neigh" or kind == "log":
        new_gt = convert(gt,True)
        data = new_gt.values
        df1 = pd.DataFrame(data=data[0:,0:],
                        index=[i for i in range(data.shape[0])],
                        columns=['f'+str(i) for i in range(1, data.shape[1]+1)])
        df2 = pd.DataFrame({'label':target})
        df = df1.join(df2)
        df.to_csv('/tmp/boolean.csv',index=False)
        csv = '/tmp/boolean.csv'
        gt = pd.read_csv(csv)

    if kind != "neigh":
        thresholds = [0.005,0.01,0.05,0.1,0.2,0.4]
        features = fs_driver(csv, kind, thresholds, True)
        data = gt[features]
    return [data, target]

def cross_validation(classifier, csv):
    cell_text = []
    for c in classifier:
        gt = preprocess(c, csv)
        data = gt[0]
        target = gt[1]
        row = []
        if classifier == "neigh":
            pca = PCA(n_components=PCA_components(csv, kind, True))
            clf = Pipeline(steps=[('scaler', preprocessing.StandardScaler()),('pca', pca), ('neigh', algo_picker(c))])
        elif classifier == "log":
            clf = Pipeline(steps=[('scaler',preprocessing.StandardScaler()), ('log', algo_picker(c))])
        else:
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
    classifiers = args.classifier if args.classifier != None else ['neigh','tree','log','forest']
    csv = args.groundtruth if args.groundtruth != None else "../../dumps/27K-22-05-T5.csv"
    cross_validation(classifiers, csv)