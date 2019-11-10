from sklearn.base import BaseEstimator
from sklearn.base import ClassifierMixin
import copy
import numpy as np

np.set_printoptions(edgeitems=15)
np.core.arrayprint._line_width = 250


class ComposedClassifier(BaseEstimator, ClassifierMixin):

    def __init__(self,
                 clf):  # clfs : list of classifiers, for now it works for only one, but could be extensible to an ensemble of classifiers later
        self.clf = clf
        self.clf_detect = copy.copy(self.clf)
        self.clf_classif = copy.copy(self.clf)
        self.classes_ = None

    def fit(self, X,
            y):  # X : np.array of vectors features for training,  y : a list of corresponding labels for training
        labels_for_detection = ['packed' if 'unpacked' not in label else label for label in
                                y]  # labels_for_detection: 'packed', 'unpacked'
        labels_for_fam_classif = [label for label in y if
                                  'unpacked' not in label]  # labels_for_fam_classif : 'ASPack', 'UPX',..., packers_families
        samples_for_fam_classif = np.array([(np.array(X[i])) for i, label in enumerate(y) if
                                            'unpacked' not in label])  # get only the vectors of features corresponding to packed samples
        self.clf_detect.fit(X,
                            labels_for_detection)  # train a first classifier which only detects whether a sample is packed or not
        self.clf_classif.fit(samples_for_fam_classif,
                             labels_for_fam_classif)  # train a second a classifier for classifiying a packed sample in its corresponding family

    def predict(self, X):  # X : np.array of features vectors for testing
        if X.ndim == 1:
            X = X.reshape(1, -1)  # if there is only one sample to test, the array of 1D should be reshaped
        detected_labels = self.clf_detect.predict(
            X).tolist()  # detect first whether the sample(s) is/are packed/unpacked
        samples_to_fam_classify = np.array([(np.array(X[i])) for i, label in enumerate(detected_labels) if
                                            label == 'packed'])  # get the packed features vectors for classification just after
        if len(
                samples_to_fam_classify) > 0:  # check whether there is/are packed sample(s) to classify into familiy(ies)
            classified_labels = self.clf_classif.predict(
                samples_to_fam_classify)  # classify the packed sample(s) in its/their corresponding family(ies)
            iterator = iter(classified_labels)
            final_class_labels = [(iterator.next()) if label == 'packed' else label for i, label in
                                  enumerate(detected_labels)]  # build the final list of labels to output
        else:
            final_class_labels = detected_labels
        return final_class_labels

    def predict_proba(self, X):  # X : np.array of features vectors for testing
        if X.ndim == 1:
            X = X.reshape(1, -1)  # if there is only one sample to test, the array of 1D should be reshaped
        detected_labels = self.clf_detect.predict(
            X).tolist()  # detect first whether the sample(s) is/are packed/unpacked
        samples_to_fam_classify = np.array([(np.array(X[i])) for i, label in enumerate(detected_labels) if
                                            label == 'packed'])  # get the packed features vectors for classification just after
        if len(
                samples_to_fam_classify) > 0:  # check whether there is/are packed sample(s) to classify into familiy(ies)
            self.classes_ = self.clf_classif.classes_
            proba_classified_labels = self.clf_classif.predict_proba(
                samples_to_fam_classify)  # classify the packed sample(s) in its/their corresponding family(ies)
            final_proba_labels = proba_classified_labels
        else:
            self.classes_ = self.clf_detect.classes_
            final_proba_labels = self.clf_detect.predict_proba(X)
        return final_proba_labels
