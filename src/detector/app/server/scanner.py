from time import perf_counter
from datetime import date
from joblib import load
from flask import Flask
from flask_restful import Resource, Api, reqparse
import pandas as pd
import numpy as np
import werkzeug, sys, os

sys.path.append('../../src')
from pefeats import Pefeats
from detector import Malware

clf = load('tree.joblib')

app = Flask(__name__)
api = Api(app)
UPLOAD_FOLDER = '/tmp'
parser = reqparse.RequestParser()
parser.add_argument('file',type=werkzeug.datastructures.FileStorage, location='files')

class MalwareUpload(Resource):
    def post(self):
        data = parser.parse_args()
        if data['file'] == "":
            return {
                    'data':'',
                    'message':'No file found',
                    'status':'error'
                    }
        malware = data['file']
        if malware:
            filename = 'to_scan'
            malware.save(os.path.join(UPLOAD_FOLDER, filename))
            today = date.today().strftime("%d/%m/%Y")
            first = perf_counter()
            features = get_features(Malware(today,UPLOAD_FOLDER+'/'+filename))
            second = perf_counter()
            decision = predict(panda_format(features))
            third = perf_counter()
            return {
                    'data':'',
                    'message': decision,
                    'extraction_time': round(second-first,5),
                    'classification_time': round(third-second,5),
                    'status':'200'
                    }
        return {
                'data':'',
                'message':'Something when wrong',
                'status':'400'
                }


api.add_resource(MalwareUpload,'/upload')

def get_features(malware):
    return Pefeats(malware).analyze()

def predict(features):
    label = clf.predict(features)[0]
    return 'packed' if label == 1 else 'not packed'

def panda_format(vector):
    columns=['f'+str(i) for i in range(1, 120)]
    f = open("tree_config.txt", "r")
    txt = f.readline()
    data = txt.split(" ")
    best_features = np.array(data)
    df = pd.DataFrame([vector], columns=columns)
    return df[best_features]


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
    
