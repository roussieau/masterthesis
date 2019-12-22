from flask import Flask
from flask import render_template
from flask import request
from database import Database


URL = "postgresql://thesis:carpestudentem@revuedesingenieurs.be/thesis"

app = Flask(__name__)
db = Database()

def convert(date):
    """ Transform dates from 20190815 to 15/08/2018"""
    cleanDate = date[0].replace('-', '')
    number = date[1]
    day = cleanDate[6:8]
    month = cleanDate[4:6]
    year = cleanDate[:4]
    newDate = '{}/{}/{}'.format(day, month, year)
    return (newDate, number, date[0])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detectors')
def detectors():
    detectors = db.getAllDetectors()
    return render_template('detectors.html', detectors=detectors)

@app.route('/malwares')
def malwares():
    dates = map(convert, db.getCountByDates())
    return render_template('malwares.html', dates=dates)

@app.route('/malwares/<date>')
def dateDetail(date):
    malwares = db.getMalwaresFromDate(date)
    return render_template('malwaresByDate.html', malwares=malwares, date=date)

@app.route('/malwares/<date>/<name>')
def malwareDetail(date, name):
    packers = db.getMalwareResult(date, name)
    features = db.getFeatureResult(date, name)
    return render_template('malwareDetail.html',
                           packers=packers,
                           name=name,
                           features=features)


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
