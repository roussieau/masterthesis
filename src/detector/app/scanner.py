from datetime import date
from flask import Flask
from flask_restful import Resource, Api, reqparse
import werkzeug, sys, os

sys.path.append('../src')
from pefeats import Pefeats
from detector import Malware


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
            decision = detect(Malware(today,UPLOAD_FOLDER+'/'+filename))
            return {
                    'data':'',
                    'message': decision,
                    'status':'success'
                    }
        return {
                'data':'',
                'message':'Something when wrong',
                'status':'error'
                }


api.add_resource(MalwareUpload,'/upload')

def detect(malware):
    return Pefeats(malware).analyze()

if __name__ == '__main__':
    app.run(host='0.0.0.0')
    
