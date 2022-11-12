import flask
from flask import request, render_template
from flask_cors import CORS
import joblib

app = flask.Flask(__name__, static_url_path='')
CORS(app)

@app.route('/', methods=['GET'])
def sendHomePage():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predictSpecies():
    sell = float(request.form['sell'])
    ot = float(request.form['ot'])
    vt = float(request.form['vt'])
    gb = float(request.form['gb'])
    pps=float(request.form['pps'])
    km=float(request.form['km'])
    ft=float(request.form['ft'])
    brand=float(request.form['brand'])
    nr=float(request.form['nr'])
    age=float(request.form['age'])
    X = [[sell, ot, vt, gb,pps,km,ft,brand,nr,age]]
    model1 = joblib.load('RandomForest.pkl')
    model2 = joblib.load('DecisionTree.pkl')
    model3 = joblib.load('XGBoost.pkl')
    rf = model1.predict(X)[0]
    dt = model2.predict(X)[0]
    xg =  model3.predict(X)[0]
    return render_template('predict.html',predict1=rf,predict2=dt,predict3=xg)

if __name__ == '__main__':
    app.run()