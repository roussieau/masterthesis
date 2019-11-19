from flask import Flask
from flask import render_template
from flask import request
from database import Database


URL = "postgresql://thesis:carpestudentem@revuedesingenieurs.be/thesis"

app = Flask(__name__)
db = Database()

@app.route('/')
def hello_world():
    return 'Hello, World!'

@app.route('/detectors')
def detectors():
    detectors = db.getDetectors()
    return render_template('index.html', detectors=detectors)

@app.route('/packers', methods=['GET', 'POST'])
def packers():
    if request.method == "POST":
        db.addChange(request.form['old'], request.form['new'])
        print(request.form['old'])
        db.updatePacker(request.form['old'], request.form['new'])
    packers = db.getPackers()
    return render_template('packers.html', packers=packers)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=80)
