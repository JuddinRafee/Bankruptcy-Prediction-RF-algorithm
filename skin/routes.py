import flask
from reportlab.platypus import PageBreak

from skin import app, User, db
from flask import render_template, url_for, redirect, request, flash, request, session, send_from_directory, send_file
from joblib import dump, load
import pandas as pd
import os
import matplotlib.pyplot as plt
from flask import Flask, render_template, redirect, url_for
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.metrics import accuracy_score

with open(f'model/BPSRFmodel13.joblib', 'rb') as f:
   model13 = load(f)
with open(f'model/BPSRFmodel36.joblib', 'rb') as f:
   model36 = load(f)
with open(f'model/BPSRFmodel41.joblib', 'rb') as f:
   model41 = load(f)
with open(f'model/BPSRFmodel54.joblib', 'rb') as f:
   model54 = load(f)
with open(f'model/BPSRFmodel64.joblib', 'rb') as f:
   model64 = load(f)


# No caching at all for API endpoints.
#@app.after_request
#def add_header(response):
    # response.cache_control.no_store = True
 #   if 'Cache-Control' not in response.headers:
  #      response.headers['Cache-Control'] = 'no-store'
   # return response
@app.route("/", methods=['GET','POST'])
@app.route("/home", methods=['GET','POST'])
def home():
    return render_template("home.html", title='HOME')


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('category'))


        invalid = 'Invalid Username and Password !! PLEASE REGISTER FIRST'
        return render_template('login.html', form=form, warning=invalid)
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        success = 'Successful Registered Account !! You can proceed to sign in'
        return render_template('login.html', form=form, success=success)
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)


@app.route("/choose_category", methods=['GET','POST'])
def category():
    return render_template("category.html", title='HOME',name=current_user.username)

#####################################################################guideline
@app.route("/guideline64", methods=['GET','POST'])
def guideline64():
    return render_template("guideline-64.html", title='HOME')
@app.route("/guideline54", methods=['GET','POST'])
def guideline54():
    return render_template("guideline-54.html", title='HOME')
@app.route("/guideline41", methods=['GET','POST'])
def guideline41():
    return render_template("guideline-41.html", title='HOME')
@app.route("/guideline36", methods=['GET','POST'])
def guideline36():
    return render_template("guideline-36.html", title='HOME')
@app.route("/guideline13", methods=['GET','POST'])
def guideline13():
    return render_template("guideline-13.html", title='HOME')
@app.route("/guidelineOwn", methods=['GET','POST'])
def guidelineOwn():
    return render_template("guideline-Own.html", title='HOME')

######################################################################insertdata
@app.route("/insertDate64", methods=['GET','POST'])
def insertData64():
    return render_template("insertData-64.html", title='HOME')
@app.route("/insertDate54", methods=['GET','POST'])
def insertData54():
    return render_template("insertData-54.html", title='HOME')
@app.route("/insertDate41", methods=['GET','POST'])
def insertData41():
    return render_template("insertData-41.html", title='HOME')
@app.route("/insertDate36", methods=['GET','POST'])
def insertData36():
    return render_template("insertData-36.html", title='HOME')
@app.route("/insertDate13", methods=['GET','POST'])
def insertData13():
    return render_template("insertData-13.html", title='HOME')
@app.route("/insertDateOwn", methods=['GET','POST'])
def insertDataOwn():
    return render_template("insertData-Own.html", title='HOME')

#######################################################################getData
@app.route('/data64', methods=['GET', 'POST'])
def data64():
    if flask.request.method == 'GET':
        return (flask.render_template('insertData-64.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "data64.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        data = pd.read_excel(f)
        return render_template('insertData-64.html', data=data.to_html())
@app.route('/data54', methods=['GET', 'POST'])
def data54():
    if flask.request.method == 'GET':
        return (flask.render_template('insertData-54.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "data54.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        data = pd.read_excel(f)
        return render_template('insertData-54.html', data=data.to_html())
@app.route('/data41', methods=['GET', 'POST'])
def data41():
    if flask.request.method == 'GET':
        return (flask.render_template('insertData-41.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "data41.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        data = pd.read_excel(f)
        return render_template('insertData-41.html', data=data.to_html())
@app.route('/data36', methods=['GET', 'POST'])
def data36():
    if flask.request.method == 'GET':
        return (flask.render_template('insertData-36.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "data36.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        data = pd.read_excel(f)
        return render_template('insertData-36.html', data=data.to_html())
@app.route('/data13', methods=['GET', 'POST'])
def data13():
    if flask.request.method == 'GET':
        return (flask.render_template('insertData-13.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "data13.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        data = pd.read_excel(f)
        return render_template('insertData-13.html', data=data.to_html())
@app.route('/dataOwn', methods=['GET', 'POST'])
def dataOwn():
    if flask.request.method == 'GET':
        return (flask.render_template('insertData-Own.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "dataOwn.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        data = pd.read_excel(f)
        return render_template('insertData-Own.html', data=data.to_html())


##############################################################################predict
@app.route('/predict64', methods=['GET', 'POST'])
def predict64():
        data = pd.read_excel(app.root_path+"\dataset\data64.xlsx")
        labels = data.columns[1:65]
        testdata = data[labels]
        predictions = model64.predict_proba(testdata)
        pd.DataFrame(predictions).to_csv("skin/dataset/resultdata64.csv")
        return render_template('predictResult-64.html',result=predictions)
@app.route('/predict54', methods=['GET', 'POST'])
def predict54():
        data = pd.read_excel(app.root_path+"\dataset\data54.xlsx")
        labels = data.columns[1:55]
        testdata = data[labels]
        predictions = model54.predict_proba(testdata)
        pd.DataFrame(predictions).to_csv("skin/dataset/resultdata54.csv")
        return render_template('predictResult-54.html',result=predictions)
@app.route('/predict41', methods=['GET', 'POST'])
def predict41():
        data = pd.read_excel(app.root_path+"\dataset\data41.xlsx")
        labels = data.columns[1:42]
        testdata = data[labels]
        predictions = model41.predict_proba(testdata)
        pd.DataFrame(predictions).to_csv("skin/dataset/resultdata41.csv")
        return render_template('predictResult-41.html',result=predictions)
@app.route('/predict36', methods=['GET', 'POST'])
def predict36():
        data = pd.read_excel(app.root_path+"\dataset\data36.xlsx")
        labels = data.columns[1:37]
        testdata = data[labels]
        predictions = model36.predict_proba(testdata)
        pd.DataFrame(predictions).to_csv("skin/dataset/resultdata36.csv")
        return render_template('predictResult-36.html',result=predictions)
@app.route('/predict13', methods=['GET', 'POST'])
def predict13():
        data = pd.read_excel(app.root_path+"\dataset\data13.xlsx")
        labels = data.columns[1:14]
        testdata = data[labels]
        predictions = model13.predict_proba(testdata)
        pd.DataFrame(predictions).to_csv("skin/dataset/resultdata13.csv")
        return render_template('predictResult-13.html',result=predictions)
@app.route('/predictOwn', methods=['GET', 'POST'])
def predictOwn():
    with open(f'skin/model/BPSRFmodelUser.joblib', 'rb') as f:
        modelOwn = load(f)
    data = pd.read_excel(app.root_path+"\dataset\dataOwn.xlsx")
    labels = data.columns[1:]
    testdata = data[labels]
    predictions = modelOwn.predict_proba(testdata)
    pd.DataFrame(predictions).to_csv("skin/dataset/resultdataOwn.csv")
    return render_template('predictResult-Own.html',result=predictions)

############################################################################plot result
@app.route('/result64', methods=['GET', 'POST'])
def plotResult64():
    #### bar compare
    data = pd.read_csv("skin/dataset/resultdata64.csv")
    notbnk = data['0']
    bnk = data['1']
    ind = range(len(data))  # the x locations for the groups
    width = 0.8
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.bar(ind, notbnk, width, color='b')
    ax.bar(ind, bnk, width, bottom=notbnk, color='r')
    ax.set_ylabel('Posibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageResult64' + '.png')
    plt.savefig(imagepath)
########### line compare
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    ax.plot(notbnk, data=data, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
    ax.plot(bnk, data=data, marker='o', markerfacecolor='red', markersize=12, color='tomato', linewidth=4)
    ax.set_ylabel('Possibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")
    ax.grid(True)

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageLineResult64' + '.png')
    plt.savefig(imagepath)
######### chart not bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, notbnk, color='b')
    for index, value in enumerate(notbnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Not Bankrupt')
    ax.set_title('Possibility Not Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageNotBnkResult64' + '.png')
    plt.savefig(imagepath)
######## chart bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, bnk, color='r')
    for index, value in enumerate(bnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Bankrupt')
    ax.set_title('Possibility Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageBnkResult64' + '.png')
    plt.savefig(imagepath)
    return render_template('visualResult-64.html', imageResult64=imagepath)
@app.route('/result54', methods=['GET', 'POST'])
def plotResult54():
    #### bar compare
    data = pd.read_csv("skin/dataset/resultdata54.csv")
    notbnk = data['0']
    bnk = data['1']
    ind = range(len(data))  # the x locations for the groups
    width = 0.8
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.bar(ind, notbnk, width, color='b')
    ax.bar(ind, bnk, width, bottom=notbnk, color='r')
    ax.set_ylabel('Posibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageResult54' + '.png')
    plt.savefig(imagepath)
########### line compare
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    ax.plot(notbnk, data=data, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
    ax.plot(bnk, data=data, marker='o', markerfacecolor='red', markersize=12, color='tomato', linewidth=4)
    ax.set_ylabel('Possibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")
    ax.grid(True)

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageLineResult54' + '.png')
    plt.savefig(imagepath)
######### chart not bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, notbnk, color='b')
    for index, value in enumerate(notbnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Not Bankrupt')
    ax.set_title('Possibility Not Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageNotBnkResult54' + '.png')
    plt.savefig(imagepath)
######## chart bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, bnk, color='r')
    for index, value in enumerate(bnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Bankrupt')
    ax.set_title('Possibility Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageBnkResult54' + '.png')
    plt.savefig(imagepath)
    return render_template('visualResult-54.html', imageResult64=imagepath)
@app.route('/result41', methods=['GET', 'POST'])
def plotResult41():
    #### bar compare
    data = pd.read_csv("skin/dataset/resultdata41.csv")
    notbnk = data['0']
    bnk = data['1']
    ind = range(len(data))  # the x locations for the groups
    width = 0.8
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.bar(ind, notbnk, width, color='b')
    ax.bar(ind, bnk, width, bottom=notbnk, color='r')
    ax.set_ylabel('Posibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageResult41' + '.png')
    plt.savefig(imagepath)
########### line compare
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    ax.plot(notbnk, data=data, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
    ax.plot(bnk, data=data, marker='o', markerfacecolor='red', markersize=12, color='tomato', linewidth=4)
    ax.set_ylabel('Possibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")
    ax.grid(True)

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageLineResult41' + '.png')
    plt.savefig(imagepath)
######### chart not bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, notbnk, color='b')
    for index, value in enumerate(notbnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Not Bankrupt')
    ax.set_title('Possibility Not Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageNotBnkResult41' + '.png')
    plt.savefig(imagepath)
######## chart bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, bnk, color='r')
    for index, value in enumerate(bnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Bankrupt')
    ax.set_title('Possibility Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageBnkResult41' + '.png')
    plt.savefig(imagepath)
    return render_template('visualResult-41.html', imageResult64=imagepath)
@app.route('/result36', methods=['GET', 'POST'])
def plotResult36():
    #### bar compare
    data = pd.read_csv("skin/dataset/resultdata36.csv")
    notbnk = data['0']
    bnk = data['1']
    ind = range(len(data))  # the x locations for the groups
    width = 0.8
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.bar(ind, notbnk, width, color='b')
    ax.bar(ind, bnk, width, bottom=notbnk, color='r')
    ax.set_ylabel('Posibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageResult36' + '.png')
    plt.savefig(imagepath)
########### line compare
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    ax.plot(notbnk, data=data, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
    ax.plot(bnk, data=data, marker='o', markerfacecolor='red', markersize=12, color='tomato', linewidth=4)
    ax.set_ylabel('Possibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")
    ax.grid(True)

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageLineResult36' + '.png')
    plt.savefig(imagepath)
######### chart not bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, notbnk, color='b')
    for index, value in enumerate(notbnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Not Bankrupt')
    ax.set_title('Possibility Not Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageNotBnkResult36' + '.png')
    plt.savefig(imagepath)
######## chart bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, bnk, color='r')
    for index, value in enumerate(bnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Bankrupt')
    ax.set_title('Possibility Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageBnkResult36' + '.png')
    plt.savefig(imagepath)
    return render_template('visualResult-36.html', imageResult64=imagepath)
@app.route('/result13', methods=['GET', 'POST'])
def plotResult13():
    #### bar compare
    data = pd.read_csv("skin/dataset/resultdata13.csv")
    notbnk = data['0']
    bnk = data['1']
    ind = range(len(data))  # the x locations for the groups
    width = 0.8
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.bar(ind, notbnk, width, color='b')
    ax.bar(ind, bnk, width, bottom=notbnk, color='r')
    ax.set_ylabel('Posibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageResult13' + '.png')
    plt.savefig(imagepath)
########### line compare
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    ax.plot(notbnk, data=data, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
    ax.plot(bnk, data=data, marker='o', markerfacecolor='red', markersize=12, color='tomato', linewidth=4)
    ax.set_ylabel('Possibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")
    ax.grid(True)

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageLineResult13' + '.png')
    plt.savefig(imagepath)
######### chart not bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, notbnk, color='b')
    for index, value in enumerate(notbnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Not Bankrupt')
    ax.set_title('Possibility Not Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageNotBnkResult13' + '.png')
    plt.savefig(imagepath)
######## chart bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, bnk, color='r')
    for index, value in enumerate(bnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Bankrupt')
    ax.set_title('Possibility Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageBnkResult13' + '.png')
    plt.savefig(imagepath)
    return render_template('visualResult-13.html', imageResult64=imagepath)
@app.route('/resultOwn', methods=['GET', 'POST'])
def plotResultOwn():
    #### bar compare
    data = pd.read_csv("skin/dataset/resultdataOwn.csv")
    notbnk = data['0']
    bnk = data['1']
    ind = range(len(data))  # the x locations for the groups
    width = 0.8
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.bar(ind, notbnk, width, color='b')
    ax.bar(ind, bnk, width, bottom=notbnk, color='r')
    ax.set_ylabel('Posibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageResultOwn' + '.png')
    plt.savefig(imagepath)
########### line compare
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])

    ax.plot(notbnk, data=data, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
    ax.plot(bnk, data=data, marker='o', markerfacecolor='red', markersize=12, color='tomato', linewidth=4)
    ax.set_ylabel('Possibility Of Bankruptcy')
    ax.set_xlabel('Company')
    ax.set_title('Comparison Possibility Bankruptcy Prediction Result')
    ax.set_facecolor("lavender")
    ax.grid(True)

    plt.xticks(ind, rotation='horizontal')
    plt.ylim(0, 1.2)
    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt', 'Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageLineResultOwn' + '.png')
    plt.savefig(imagepath)
######### chart not bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, notbnk, color='b')
    for index, value in enumerate(notbnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Not Bankrupt')
    ax.set_title('Possibility Not Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Not Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageNotBnkResultOwn' + '.png')
    plt.savefig(imagepath)
######## chart bankrupt
    fig = plt.figure(figsize=(9, 5))
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
    ax.barh(ind, bnk, color='r')
    for index, value in enumerate(bnk):
        plt.text(value, index, str("{:.0%}".format(value)))
    ax.set_ylabel('Company')
    ax.set_xlabel('Possibility Of Bankrupt')
    ax.set_title('Possibility Bankrupt Prediction Result ')
    ax.set_facecolor("lavender")
    plt.yticks(ind)

    # Tweak spacing to prevent clipping of tick-labels
    plt.subplots_adjust(bottom=0.15)
    ax.legend(labels=['Bankrupt'], fontsize=8)

    imagepath = os.path.join('skin/static/images', 'imageBnkResultOwn' + '.png')
    plt.savefig(imagepath)
    return render_template('visualResult-Own.html', imageResult64=imagepath)

############################################################################insert variable
@app.route("/insertVariable64", methods=['GET','POST'])
def insertAttr64():
    return render_template("visualData-64.html", title='HOME')
@app.route("/insertVariable54", methods=['GET','POST'])
def insertAttr54():
    return render_template("visualData-54.html", title='HOME')
@app.route("/insertVariable41", methods=['GET','POST'])
def insertAttr41():
    return render_template("visualData-41.html", title='HOME')
@app.route("/insertVariable36", methods=['GET','POST'])
def insertAttr36():
    return render_template("visualData-36.html", title='HOME')
@app.route("/insertVariable13", methods=['GET','POST'])
def insertAttr13():
    return render_template("visualData-13.html", title='HOME')

###############################################################################plotData
@app.route('/Data64', methods=['GET', 'POST'])
def plotData64():
    if request.method == 'POST':
        data = pd.read_excel("skin/dataset/data64.xlsx")
        variable = request.form['variables']
        attr = data[variable]
        ind = range(len(data))
        dataT = pd.read_csv("skin/dataset/bankruptcyTrain.csv")



        fig = plt.figure(figsize=(15, 10))
        ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
        # 'bo-' means blue color, round points, solid lines
        ax.plot(ind, attr, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
        if variable == "Attr1":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr1"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr2":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr2"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr3":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr3"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr4":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr4"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "current assets / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr5":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr5"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "[(cash + short-term securities + receivables - short-term liabilities) / (operating expenses - depreciation)] * 365"')
            ax.plot(x, y, color='r')
        if variable == "Attr6":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr6"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "retained earnings / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr7":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr7"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBIT / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr8":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr8"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "book value of equity / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr9":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr9"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr10":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr10"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "equity / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr11":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr11"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + extraordinary items + financial expenses) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr12":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr12"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr13":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr13"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr14":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr14"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + interest) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr15":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr15"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities * 365) / (gross profit + depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr16":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr16"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr17":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr17"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr18":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr18"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr19":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr19"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr20":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr20"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(inventory * 365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr21":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr21"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales (n) / sales (n-1)"')
            ax.plot(x, y, color='r')
        if variable == "Attr22":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr22"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr23":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr23"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr24":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr24"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit (in 3 years) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr25":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr25"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(equity - share capital) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr26":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr26"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(net profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr27":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr27"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / financial expenses"')
            ax.plot(x, y, color='r')
        if variable == "Attr28":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr28"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr29":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr29"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "logarithm of total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr30":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr30"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities - cash) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr31":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr31"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + interest) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr32":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr32"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current liabilities * 365) / cost of products sold"')
            ax.plot(x, y, color='r')
        if variable == "Attr33":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr33"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "operating expenses / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr34":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr34"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "operating expenses / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr35":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr35"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr36":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr36"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr37":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr37"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventories) / long-term liabilities "')
            ax.plot(x, y, color='r')
        if variable == "Attr38":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr38"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "constant capital / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr39":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr39"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr40":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr40"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory - receivables) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr41":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr40"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / ((profit on operating activities + depreciation) * (12/365))"')
            ax.plot(x, y, color='r')
        if variable == "Attr42":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr42"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr43":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr43"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "rotation receivables + inventory turnover in days"')
            ax.plot(x, y, color='r')
        if variable == "Attr44":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr44"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(receivables * 365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr45":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr45"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / inventory"')
            ax.plot(x, y, color='r')
        if variable == "Attr46":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr46"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr47":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr47"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(inventory * 365) / cost of products sold"')
            ax.plot(x, y, color='r')
        if variable == "Attr48":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr48"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr49":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr49"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr50":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr50"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "current assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr51":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr51"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "short-term liabilities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr52":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr52"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(short-term liabilities * 365) / cost of products sold)"')
            ax.plot(x, y, color='r')
        if variable == "Attr53":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr53"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "equity / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr54":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr54"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "constant capital / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr55":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr55"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital"')
            ax.plot(x, y, color='r')
        if variable == "Attr56":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr56"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(sales - cost of products sold) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr57":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr57"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory - short-term liabilities) / (sales - gross profit - depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr58":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr58"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total costs /total sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr59":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr59"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "long-term liabilities / equity"')
            ax.plot(x, y, color='r')
        if variable == "Attr60":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr60"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / inventory"')
            ax.plot(x, y, color='r')
        if variable == "Attr61":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr61"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / receivables"')
            ax.plot(x, y, color='r')
        if variable == "Attr62":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr62"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(short-term liabilities *365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr63":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr63"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr64":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr64"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / fixed assets"')
            ax.plot(x, y, color='r')

        ax.set_ylabel('Attribute Value')
        ax.set_xlabel('Company')
        ax.set_facecolor("lavender")
        ax.legend(labels=[variable,"Mean value from 10,000 Not-Bankrupt company"], fontsize=10)
        ax.grid(True)

        plt.xticks(ind, rotation='horizontal')

        # Tweak spacing to prevent clipping of tick-labels
        plt.subplots_adjust(bottom=0.15)
        # zip joins x and y coordinates in pairs
        for x, y in zip(ind, attr):
            label = "{:.3f}".format(y)

            plt.annotate(label,  # this is the text
                         (x, y),  # this is the point to label
                         textcoords="offset points",  # how to position the text
                         xytext=(0, 10),  # distance from text to points (x,y)
                         ha='center')  # horizontal alignment can be left, right or center

        imagepath = os.path.join('skin/static/images', 'imageLineData64' + '.png')
        plt.savefig(imagepath)

    return render_template('visualDataCon-64.html')
@app.route('/Data54', methods=['GET', 'POST'])
def plotData54():
    if request.method == 'POST':
        data = pd.read_excel("skin/dataset/data54.xlsx")
        variable = request.form['variables']
        attr = data[variable]
        ind = range(len(data))
        dataT = pd.read_csv("skin/dataset/bankruptcyTrain.csv")

        fig = plt.figure(figsize=(15, 10))
        ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
        # 'bo-' means blue color, round points, solid lines
        ax.plot(ind, attr, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
        if variable == "Attr1":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr2"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr2":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr4"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "current assets / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr3":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr5"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "[(cash + short-term securities + receivables - short-term liabilities) / (operating expenses - depreciation)] * 365"')
            ax.plot(x, y, color='r')
        if variable == "Attr4":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr6"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "retained earnings / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr5":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr8"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "book value of equity / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr6":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr9"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr7":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr10"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "equity / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr8":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr11"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + extraordinary items + financial expenses) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr9":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr12"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr10":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr13"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr11":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr13"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + interest) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr12":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr15"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities * 365) / (gross profit + depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr13":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr16"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr14":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr17"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr15":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr18"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr16":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr19"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr17":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr20"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(inventory * 365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr18":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr23"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr19":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr24"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit (in 3 years) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr20":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr25"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(equity - share capital) / total assets "')
            ax.plot(x, y, color='r')
        if variable == "Attr21":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr26"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(net profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr22":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr27"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / financial expenses "')
            ax.plot(x, y, color='r')
        if variable == "Attr23":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr28"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr24":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr29"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "logarithm of total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr25":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr30"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities - cash) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr26":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr32"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current liabilities * 365) / cost of products sold"')
            ax.plot(x, y, color='r')
        if variable == "Attr27":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr34"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "operating expenses / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr28":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr35"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr29":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr36"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr30":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr37"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventories) / long-term liabilities "')
            ax.plot(x, y, color='r')
        if variable == "Attr31":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr38"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "constant capital / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr32":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr39"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr33":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr40"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory - receivables) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr34":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr41"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / ((profit on operating activities + depreciation) * (12/365))"')
            ax.plot(x, y, color='r')
        if variable == "Attr35":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr42"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr36":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr44"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(receivables * 365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr37":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr45"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / inventory"')
            ax.plot(x, y, color='r')
        if variable == "Attr38":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr46"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr39":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr48"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr40":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr49"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr41":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr50"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "current assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr42":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr51"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "short-term liabilities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr43":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr52"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(short-term liabilities * 365) / cost of products sold)"')
            ax.plot(x, y, color='r')
        if variable == "Attr44":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr53"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "equity / fixed asset"')
            ax.plot(x, y, color='r')
        if variable == "Attr45":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr54"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "constant capital / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr46":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr55"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital"')
            ax.plot(x, y, color='r')
        if variable == "Attr47":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr56"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(sales - cost of products sold) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr48":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr57"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory - short-term liabilities) / (sales - gross profit - depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr49":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr58"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total costs /total sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr50":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr59"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "long-term liabilities / equity"')
            ax.plot(x, y, color='r')
        if variable == "Attr51":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr60"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / inventory"')
            ax.plot(x, y, color='r')
        if variable == "Attr52":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr61"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / receivables"')
            ax.plot(x, y, color='r')
        if variable == "Attr53":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr62"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(short-term liabilities *365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr54":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr63"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / short-term liabilities"')
            ax.plot(x, y, color='r')

        ax.set_ylabel('Attribute Value')
        ax.set_xlabel('Company')
        ax.set_facecolor("lavender")
        ax.legend(labels=[variable,"Mean value from 10,000 Not-Bankrupt company"], fontsize=8)
        ax.grid(True)

        plt.xticks(ind, rotation='horizontal')

        # Tweak spacing to prevent clipping of tick-labels
        plt.subplots_adjust(bottom=0.15)
        # zip joins x and y coordinates in pairs
        for x, y in zip(ind, attr):
            label = "{:.3f}".format(y)

            plt.annotate(label,  # this is the text
                         (x, y),  # this is the point to label
                         textcoords="offset points",  # how to position the text
                         xytext=(0, 10),  # distance from text to points (x,y)
                         ha='center')  # horizontal alignment can be left, right or center

        imagepath = os.path.join('skin/static/images', 'imageLineData54' + '.png')
        plt.savefig(imagepath)

    return render_template('visualDataCon-54.html')
@app.route('/Data41', methods=['GET', 'POST'])
def plotData41():
    if request.method == 'POST':
        data = pd.read_excel("skin/dataset/data41.xlsx")
        variable = request.form['variables']
        attr = data[variable]
        ind = range(len(data))
        dataT = pd.read_csv("skin/dataset/bankruptcyTrain.csv")

        fig = plt.figure(figsize=(15, 10))
        ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
        # 'bo-' means blue color, round points, solid lines
        ax.plot(ind, attr, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
        if variable == "Attr1":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr2"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr2":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr5"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "[(cash + short-term securities + receivables - short-term liabilities) / (operating expenses - depreciation)] * 365"')
            ax.plot(x, y, color='r')
        if variable == "Attr3":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr6"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "retained earnings / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr4":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr8"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "book value of equity / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr5":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr9"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr6":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr12"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr7":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr13"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr8":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr15"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities * 365) / (gross profit + depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr9":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr16"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr10":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr17"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr11":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr20"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(inventory * 365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr12":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr23"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr13":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr24"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit (in 3 years) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr14":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr25"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(equity - share capital) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr15":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr26"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(net profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr16":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr27"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / financial expenses"')
            ax.plot(x, y, color='r')
        if variable == "Attr17":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr29"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "logarithm of total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr18":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr30"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities - cash) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr19":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr32"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current liabilities * 365) / cost of products sold"')
            ax.plot(x, y, color='r')
        if variable == "Attr20":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr34"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "operating expenses / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr21":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr35"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr22":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr37"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventories) / long-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr23":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr38"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "constant capital / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr24":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr39"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr25":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr41"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / ((profit on operating activities + depreciation) * (12/365))"')
            ax.plot(x, y, color='r')
        if variable == "Attr26":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr42"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr27":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr45"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / inventory"')
            ax.plot(x, y, color='r')
        if variable == "Attr28":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr46"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr29":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr48"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr30":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr49"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr31":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr50"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "current assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr32":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr53"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "equity / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr33":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr54"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "constant capital / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr34":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr55"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital"')
            ax.plot(x, y, color='r')
        if variable == "Attr35":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr56"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(sales - cost of products sold) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr36":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr57"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory - short-term liabilities) / (sales - gross profit - depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr37":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr58"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total costs /total sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr38":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr59"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "long-term liabilities / equity"')
            ax.plot(x, y, color='r')
        if variable == "Attr39":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr61"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / receivables"')
            ax.plot(x, y, color='r')
        if variable == "Attr40":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr62"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(short-term liabilities *365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr41":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr63"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / short-term liabilities"')
            ax.plot(x, y, color='r')

        ax.set_ylabel('Attribute Value')
        ax.set_xlabel('Company')
        ax.set_facecolor("lavender")
        ax.legend(labels=[variable,"Mean value from 10,000 Not-Bankrupt company"], fontsize=8)
        ax.grid(True)

        plt.xticks(ind, rotation='horizontal')

        # Tweak spacing to prevent clipping of tick-labels
        plt.subplots_adjust(bottom=0.15)
        # zip joins x and y coordinates in pairs
        for x, y in zip(ind, attr):
            label = "{:.3f}".format(y)

            plt.annotate(label,  # this is the text
                         (x, y),  # this is the point to label
                         textcoords="offset points",  # how to position the text
                         xytext=(0, 10),  # distance from text to points (x,y)
                         ha='center')  # horizontal alignment can be left, right or center

        imagepath = os.path.join('skin/static/images', 'imageLineData41' + '.png')
        plt.savefig(imagepath)

    return render_template('visualDataCon-41.html')
@app.route('/Data36', methods=['GET', 'POST'])
def plotData36():
    if request.method == 'POST':
        data = pd.read_excel("skin/dataset/data36.xlsx")
        variable = request.form['variables']
        attr = data[variable]
        ind = range(len(data))
        dataT = pd.read_csv("skin/dataset/bankruptcyTrain.csv")

        fig = plt.figure(figsize=(15, 10))
        ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
        # 'bo-' means blue color, round points, solid lines
        ax.plot(ind, attr, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
        if variable == "Attr1":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr2"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr2":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr5"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "[(cash + short-term securities + receivables - short-term liabilities) / (operating expenses - depreciation)] * 365"')
            ax.plot(x, y, color='r')
        if variable == "Attr3":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr6"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "retained earnings / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr4":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr9"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr5":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr12"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr6":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr13"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr7":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr15"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities * 365) / (gross profit + depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr8":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr16"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr9":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr17"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total assets / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr10":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr20"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(inventory * 365) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr11":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr23"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr12":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr24"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "gross profit (in 3 years) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr13":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr25"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(equity - share capital) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr14":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr26"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(net profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr15":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr27"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / financial expenses"')
            ax.plot(x, y, color='r')
        if variable == "Attr16":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr29"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "logarithm of total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr17":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr30"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(total liabilities - cash) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr18":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr32"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current liabilities * 365) / cost of products sold"')
            ax.plot(x, y, color='r')
        if variable == "Attr19":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr34"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "operating expenses / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr20":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr35"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr21":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr37"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventories) / long-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr22":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr39"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr23":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr41"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total liabilities / ((profit on operating activities + depreciation) * (12/365))"')
            ax.plot(x, y, color='r')
        if variable == "Attr24":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr42"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr25":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr45"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "net profit / inventory"')
            ax.plot(x, y, color='r')
        if variable == "Attr26":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr46"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr27":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr48"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr28":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr49"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr29":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr50"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "EBITDA (profit on operating activities - depreciation) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr30":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr53"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "equity / fixed assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr31":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr55"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "working capital"')
            ax.plot(x, y, color='r')
        if variable == "Attr32":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr57"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory - short-term liabilities) / (sales - gross profit - depreciation)"')
            ax.plot(x, y, color='r')
        if variable == "Attr33":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr58"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total costs /total sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr34":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr59"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "long-term liabilities / equity"')
            ax.plot(x, y, color='r')
        if variable == "Attr35":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr61"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / receivables"')
            ax.plot(x, y, color='r')
        if variable == "Attr36":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr62"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(short-term liabilities *365) / sales"')
            ax.plot(x, y, color='r')
        ax.set_ylabel('Attribute Value')
        ax.set_xlabel('Company')
        ax.set_facecolor("lavender")
        ax.legend(labels=[variable,"Mean value from 10,000 Not-Bankrupt company"], fontsize=8)
        ax.grid(True)

        plt.xticks(ind, rotation='horizontal')

        # Tweak spacing to prevent clipping of tick-labels
        plt.subplots_adjust(bottom=0.15)
        # zip joins x and y coordinates in pairs
        for x, y in zip(ind, attr):
            label = "{:.3f}".format(y)

            plt.annotate(label,  # this is the text
                         (x, y),  # this is the point to label
                         textcoords="offset points",  # how to position the text
                         xytext=(0, 10),  # distance from text to points (x,y)
                         ha='center')  # horizontal alignment can be left, right or center

        imagepath = os.path.join('skin/static/images', 'imageLineData36' + '.png')
        plt.savefig(imagepath)

    return render_template('visualDataCon-36.html')
@app.route('/Data13', methods=['GET', 'POST'])
def plotData13():
    if request.method == 'POST':
        data = pd.read_excel("skin/dataset/data13.xlsx")
        variable = request.form['variables']
        attr = data[variable]
        ind = range(len(data))
        dataT = pd.read_csv("skin/dataset/bankruptcyTrain.csv")

        fig = plt.figure(figsize=(15, 10))
        ax = fig.add_axes([0.1, 0.1, 0.8, 0.8])
        # 'bo-' means blue color, round points, solid lines
        ax.plot(ind, attr, marker='o', markerfacecolor='blue', markersize=12, color='skyblue', linewidth=4)
        if variable == "Attr1":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr5"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "[(cash + short-term securities + receivables - short-term liabilities) / (operating expenses - depreciation)] * 365"')
            ax.plot(x, y, color='r')
        if variable == "Attr2":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr6"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "retained earnings / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr3":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr9"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "sales / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr4":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr13"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr5":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr16"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(gross profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr6":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr25"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(equity - share capital) / total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr7":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr26"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(net profit + depreciation) / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr8":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr27"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on operating activities / financial expenses"')
            ax.plot(x, y, color='r')
        if variable == "Attr9":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr29"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "logarithm of total assets"')
            ax.plot(x, y, color='r')
        if variable == "Attr10":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr34"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "operating expenses / total liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr11":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr39"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "profit on sales / sales"')
            ax.plot(x, y, color='r')
        if variable == "Attr12":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr46"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "(current assets - inventory) / short-term liabilities"')
            ax.plot(x, y, color='r')
        if variable == "Attr13":
            df_split = dataT[dataT['target'] == 0]
            mean = df_split["Attr58"].mean()
            x = [0, len(data) - 1]
            y = [mean, mean]
            ax.set_title('Plot of "total costs /total sales"')
            ax.plot(x, y, color='r')

        ax.set_ylabel('Attribute Value')
        ax.set_xlabel('Company')
        ax.set_facecolor("lavender")
        ax.legend(labels=[variable,"Mean value from 10,000 Not-Bankrupt company"], fontsize=8)
        ax.grid(True)

        plt.xticks(ind, rotation='horizontal')

        # Tweak spacing to prevent clipping of tick-labels
        plt.subplots_adjust(bottom=0.15)
        # zip joins x and y coordinates in pairs
        for x, y in zip(ind, attr):
            label = "{:.3f}".format(y)

            plt.annotate(label,  # this is the text
                         (x, y),  # this is the point to label
                         textcoords="offset points",  # how to position the text
                         xytext=(0, 10),  # distance from text to points (x,y)
                         ha='center')  # horizontal alignment can be left, right or center

        imagepath = os.path.join('skin/static/images', 'imageLineData13' + '.png')
        plt.savefig(imagepath)

    return render_template('visualDataCon-13.html')

##############################################combineDF
@app.route('/combine64', methods=['GET', 'POST'])
def combine64():
    df1 = pd.read_excel("skin/dataset/data64.xlsx")
    df2 = pd.read_csv("skin/dataset/resultdata64.csv")
    df2.rename(columns={'Unnamed: 0': 'ResultIndex'}, inplace=True)
    df3 = pd.merge(df1, df2, right_index=True, left_index = True)
    pd.DataFrame(df3).to_csv("skin/dataset/finaldataset-64.csv")
    return render_template('combinedf-64.html', data=df3.to_html())
@app.route('/combine54', methods=['GET', 'POST'])
def combine54():
    df1 = pd.read_excel("skin/dataset/data54.xlsx")
    df2 = pd.read_csv("skin/dataset/resultdata54.csv")
    df2.rename(columns={'Unnamed: 0': 'ResultIndex'}, inplace=True)
    df3 = pd.merge(df1, df2, right_index=True, left_index = True)
    pd.DataFrame(df3).to_csv("skin/dataset/finaldataset-54.csv")
    return render_template('combinedf-54.html', data=df3.to_html())
@app.route('/combine41', methods=['GET', 'POST'])
def combine41():
    df1 = pd.read_excel("skin/dataset/data41.xlsx")
    df2 = pd.read_csv("skin/dataset/resultdata41.csv")
    df2.rename(columns={'Unnamed: 0': 'ResultIndex'}, inplace=True)
    df3 = pd.merge(df1, df2, right_index=True, left_index = True)
    pd.DataFrame(df3).to_csv("skin/dataset/finaldataset-41.csv")
    return render_template('combinedf-41.html', data=df3.to_html())
@app.route('/combine36', methods=['GET', 'POST'])
def combine36():
    df1 = pd.read_excel("skin/dataset/data36.xlsx")
    df2 = pd.read_csv("skin/dataset/resultdata36.csv")
    df2.rename(columns={'Unnamed: 0': 'ResultIndex'}, inplace=True)
    df3 = pd.merge(df1, df2, right_index=True, left_index = True)
    pd.DataFrame(df3).to_csv("skin/dataset/finaldataset-36.csv")
    return render_template('combinedf-36.html', data=df3.to_html())
@app.route('/combine13', methods=['GET', 'POST'])
def combine13():
    df1 = pd.read_excel("skin/dataset/data13.xlsx")
    df2 = pd.read_csv("skin/dataset/resultdata13.csv")
    df2.rename(columns={'Unnamed: 0': 'ResultIndex'}, inplace=True)
    df3 = pd.merge(df1, df2, right_index=True, left_index = True)
    pd.DataFrame(df3).to_csv("skin/dataset/finaldataset-13.csv")
    return render_template('combinedf-13.html', data=df3.to_html())
@app.route('/combineOwn', methods=['GET', 'POST'])
def combineOwn():
    df1 = pd.read_excel("skin/dataset/dataOwn.xlsx")
    df2 = pd.read_csv("skin/dataset/resultdataOwn.csv")
    df2.rename(columns={'Unnamed: 0': 'ResultIndex'}, inplace=True)
    df3 = pd.merge(df1, df2, right_index=True, left_index = True)
    pd.DataFrame(df3).to_csv("skin/dataset/finaldataset-Own.csv")
    return render_template('combinedf-Own.html', data=df3.to_html())

################################################downloadResult
@app.route("/download64")
def downloadResult64():
    p = "dataset/finaldataset-64.csv"
    return send_file(p, as_attachment=True)
@app.route("/download54")
def downloadResult54():
    p = "dataset/finaldataset-54.csv"
    return send_file(p, as_attachment=True)
@app.route("/download41")
def downloadResult41():
    p = "dataset/finaldataset-41.csv"
    return send_file(p, as_attachment=True)
@app.route("/download64")
def downloadResult36():
    p = "dataset/finaldataset-36.csv"
    return send_file(p, as_attachment=True)
@app.route("/download13")
def downloadResult13():
    p = "dataset/finaldataset-13.csv"
    return send_file(p, as_attachment=True)
@app.route("/downloadOwn")
def downloadResultOwn():
    p = "dataset/finaldataset-Own.csv"
    return send_file(p, as_attachment=True)

####################################PDF feport ######
@app.route("/downloadPDF64")
def downloadPDF64():
    def drawMyRuler(pdf):
        pdf.drawString(100,810, 'x100')
        pdf.drawString(200,810, 'x200')
        pdf.drawString(300,810, 'x300')
        pdf.drawString(400,810, 'x400')
        pdf.drawString(500,810, 'x500')

        pdf.drawString(10,100, 'y100')
        pdf.drawString(10,200, 'y200')
        pdf.drawString(10,300, 'y300')
        pdf.drawString(10,400, 'y400')
        pdf.drawString(10,500, 'y500')
        pdf.drawString(10,600, 'y600')
        pdf.drawString(10,700, 'y700')
        pdf.drawString(10,800, 'y800')

    # ###################################
    # Content
    fileName = 'skin/report/ReportResultVisualisation.pdf'
    documentTitle = 'Bankruptcy Prediction Report'



    from reportlab.lib.units import mm


    # ###################################
    # 0) Create document
    from reportlab.pdfgen import canvas
    pdf = canvas.Canvas(fileName)
    pdf.setTitle(documentTitle)

    #drawMyRuler(pdf)
    # ###################################
    # 1) Title :: Set fonts
    # # Print available fonts
    # for font in pdf.getAvailableFonts():
    #     print(font)

    # Register a new font
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics


    pdf.setFont('Courier-Bold', 30)
    pdf.drawCentredString(300,500, 'Bankruptcy Prediction Result')
    pdf.drawCentredString(300, 470, 'Data Visulisation Report')
    pdf.setFont("Courier-Bold", 10)
    pdf.drawCentredString(290, 440, 'Created by Bankruptcy Prediction System')
    pdf.showPage()

    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')


    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageBnkResult64.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility moving toward bankruptcy?',
        '2) Which company have lowest possibility moving toward bankruptcy?',
        '3) Why you should not invest in this company?',
        '4) Are this company qualified to get loan?',
        '5) Why this company should file for bankruptcy?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Not Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageNotBnkResult64.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Not Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility result for not bankrupt?',
        '2) Which company have lowest possibility result for not bankrupt?',
        '3) Which company is the best company to make investment?',
        '4) Are this company qualified to get loan?',
        '5) Are the company in a good financial condition?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageResult64.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the comparison between bankrupt',
        'and not bankrupt prediction result of the companies.',
        '',
        'A stacked bar graph (or stacked bar chart) is a chart that uses bars to',
        'show comparisons between categories of data, but with ability to break ',
        'down and compare parts of a whole. Each bar in the chart represents a ',
        'whole, and segments in the bar represent different parts or categories ',
        'of that whole.'

    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageLineResult64.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above it show another type of graph which is line ',
        'graph that can be use to make the comparison between the possibility ',
        'of bankrupt and not bankrupt.',
        '',
        'A line chart or line plot or line graph or curve chart is a type of chart',
        'which displays information as a series of data points called markers',
        'connected by straight line segments.'
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)



    pdf.save()
    return send_file("report/ReportResultVisualisation.pdf", as_attachment=True)

@app.route("/downloadPDF54")
def downloadPDF54():
    def drawMyRuler(pdf):
        pdf.drawString(100,810, 'x100')
        pdf.drawString(200,810, 'x200')
        pdf.drawString(300,810, 'x300')
        pdf.drawString(400,810, 'x400')
        pdf.drawString(500,810, 'x500')

        pdf.drawString(10,100, 'y100')
        pdf.drawString(10,200, 'y200')
        pdf.drawString(10,300, 'y300')
        pdf.drawString(10,400, 'y400')
        pdf.drawString(10,500, 'y500')
        pdf.drawString(10,600, 'y600')
        pdf.drawString(10,700, 'y700')
        pdf.drawString(10,800, 'y800')

    # ###################################
    # Content
    fileName = 'skin/report/ReportResultVisualisation.pdf'
    documentTitle = 'Bankruptcy Prediction Report'



    from reportlab.lib.units import mm


    # ###################################
    # 0) Create document
    from reportlab.pdfgen import canvas
    pdf = canvas.Canvas(fileName)
    pdf.setTitle(documentTitle)

    #drawMyRuler(pdf)
    # ###################################
    # 1) Title :: Set fonts
    # # Print available fonts
    # for font in pdf.getAvailableFonts():
    #     print(font)

    # Register a new font
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics


    pdf.setFont('Courier-Bold', 30)
    pdf.drawCentredString(300,500, 'Bankruptcy Prediction Result')
    pdf.drawCentredString(300, 470, 'Data Visulisation Report')
    pdf.setFont("Courier-Bold", 10)
    pdf.drawCentredString(290, 440, 'Created by Bankruptcy Prediction System')
    pdf.showPage()

    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')


    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageBnkResult54.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility moving toward bankruptcy?',
        '2) Which company have lowest possibility moving toward bankruptcy?',
        '3) Why you should not invest in this company?',
        '4) Are this company qualified to get loan?',
        '5) Why this company should file for bankruptcy?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Not Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageNotBnkResult54.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Not Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility result for not bankrupt?',
        '2) Which company have lowest possibility result for not bankrupt?',
        '3) Which company is the best company to make investment?',
        '4) Are this company qualified to get loan?',
        '5) Are the company in a good financial condition?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageResult54.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the comparison between bankrupt',
        'and not bankrupt prediction result of the companies.',
        '',
        'A stacked bar graph (or stacked bar chart) is a chart that uses bars to',
        'show comparisons between categories of data, but with ability to break ',
        'down and compare parts of a whole. Each bar in the chart represents a ',
        'whole, and segments in the bar represent different parts or categories ',
        'of that whole.'

    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageLineResult54.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above it show another type of graph which is line ',
        'graph that can be use to make the comparison between the possibility ',
        'of bankrupt and not bankrupt.',
        '',
        'A line chart or line plot or line graph or curve chart is a type of chart',
        'which displays information as a series of data points called markers',
        'connected by straight line segments.'
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)



    pdf.save()
    return send_file("report/ReportResultVisualisation.pdf", as_attachment=True)

@app.route("/downloadPDF41")
def downloadPDF41():
    def drawMyRuler(pdf):
        pdf.drawString(100,810, 'x100')
        pdf.drawString(200,810, 'x200')
        pdf.drawString(300,810, 'x300')
        pdf.drawString(400,810, 'x400')
        pdf.drawString(500,810, 'x500')

        pdf.drawString(10,100, 'y100')
        pdf.drawString(10,200, 'y200')
        pdf.drawString(10,300, 'y300')
        pdf.drawString(10,400, 'y400')
        pdf.drawString(10,500, 'y500')
        pdf.drawString(10,600, 'y600')
        pdf.drawString(10,700, 'y700')
        pdf.drawString(10,800, 'y800')

    # ###################################
    # Content
    fileName = 'skin/report/ReportResultVisualisation.pdf'
    documentTitle = 'Bankruptcy Prediction Report'



    from reportlab.lib.units import mm


    # ###################################
    # 0) Create document
    from reportlab.pdfgen import canvas
    pdf = canvas.Canvas(fileName)
    pdf.setTitle(documentTitle)

    #drawMyRuler(pdf)
    # ###################################
    # 1) Title :: Set fonts
    # # Print available fonts
    # for font in pdf.getAvailableFonts():
    #     print(font)

    # Register a new font
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics


    pdf.setFont('Courier-Bold', 30)
    pdf.drawCentredString(300,500, 'Bankruptcy Prediction Result')
    pdf.drawCentredString(300, 470, 'Data Visulisation Report')
    pdf.setFont("Courier-Bold", 10)
    pdf.drawCentredString(290, 440, 'Created by Bankruptcy Prediction System')
    pdf.showPage()

    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')


    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageBnkResult41.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility moving toward bankruptcy?',
        '2) Which company have lowest possibility moving toward bankruptcy?',
        '3) Why you should not invest in this company?',
        '4) Are this company qualified to get loan?',
        '5) Why this company should file for bankruptcy?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Not Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageNotBnkResult41.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Not Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility result for not bankrupt?',
        '2) Which company have lowest possibility result for not bankrupt?',
        '3) Which company is the best company to make investment?',
        '4) Are this company qualified to get loan?',
        '5) Are the company in a good financial condition?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageResult41.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the comparison between bankrupt',
        'and not bankrupt prediction result of the companies.',
        '',
        'A stacked bar graph (or stacked bar chart) is a chart that uses bars to',
        'show comparisons between categories of data, but with ability to break ',
        'down and compare parts of a whole. Each bar in the chart represents a ',
        'whole, and segments in the bar represent different parts or categories ',
        'of that whole.'

    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageLineResult41.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above it show another type of graph which is line ',
        'graph that can be use to make the comparison between the possibility ',
        'of bankrupt and not bankrupt.',
        '',
        'A line chart or line plot or line graph or curve chart is a type of chart',
        'which displays information as a series of data points called markers',
        'connected by straight line segments.'
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)



    pdf.save()
    return send_file("report/ReportResultVisualisation.pdf", as_attachment=True)

@app.route("/downloadPDF36")
def downloadPDF36():
    def drawMyRuler(pdf):
        pdf.drawString(100,810, 'x100')
        pdf.drawString(200,810, 'x200')
        pdf.drawString(300,810, 'x300')
        pdf.drawString(400,810, 'x400')
        pdf.drawString(500,810, 'x500')

        pdf.drawString(10,100, 'y100')
        pdf.drawString(10,200, 'y200')
        pdf.drawString(10,300, 'y300')
        pdf.drawString(10,400, 'y400')
        pdf.drawString(10,500, 'y500')
        pdf.drawString(10,600, 'y600')
        pdf.drawString(10,700, 'y700')
        pdf.drawString(10,800, 'y800')

    # ###################################
    # Content
    fileName = 'skin/report/ReportResultVisualisation.pdf'
    documentTitle = 'Bankruptcy Prediction Report'



    from reportlab.lib.units import mm


    # ###################################
    # 0) Create document
    from reportlab.pdfgen import canvas
    pdf = canvas.Canvas(fileName)
    pdf.setTitle(documentTitle)

    #drawMyRuler(pdf)
    # ###################################
    # 1) Title :: Set fonts
    # # Print available fonts
    # for font in pdf.getAvailableFonts():
    #     print(font)

    # Register a new font
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics


    pdf.setFont('Courier-Bold', 30)
    pdf.drawCentredString(300,500, 'Bankruptcy Prediction Result')
    pdf.drawCentredString(300, 470, 'Data Visulisation Report')
    pdf.setFont("Courier-Bold", 10)
    pdf.drawCentredString(290, 440, 'Created by Bankruptcy Prediction System')
    pdf.showPage()

    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')


    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageBnkResult36.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility moving toward bankruptcy?',
        '2) Which company have lowest possibility moving toward bankruptcy?',
        '3) Why you should not invest in this company?',
        '4) Are this company qualified to get loan?',
        '5) Why this company should file for bankruptcy?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Not Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageNotBnkResult36.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Not Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility result for not bankrupt?',
        '2) Which company have lowest possibility result for not bankrupt?',
        '3) Which company is the best company to make investment?',
        '4) Are this company qualified to get loan?',
        '5) Are the company in a good financial condition?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageResult36.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the comparison between bankrupt',
        'and not bankrupt prediction result of the companies.',
        '',
        'A stacked bar graph (or stacked bar chart) is a chart that uses bars to',
        'show comparisons between categories of data, but with ability to break ',
        'down and compare parts of a whole. Each bar in the chart represents a ',
        'whole, and segments in the bar represent different parts or categories ',
        'of that whole.'

    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageLineResult36.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above it show another type of graph which is line ',
        'graph that can be use to make the comparison between the possibility ',
        'of bankrupt and not bankrupt.',
        '',
        'A line chart or line plot or line graph or curve chart is a type of chart',
        'which displays information as a series of data points called markers',
        'connected by straight line segments.'
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)



    pdf.save()
    return send_file("report/ReportResultVisualisation.pdf", as_attachment=True)

@app.route("/downloadPDF13")
def downloadPDF13():
    def drawMyRuler(pdf):
        pdf.drawString(100,810, 'x100')
        pdf.drawString(200,810, 'x200')
        pdf.drawString(300,810, 'x300')
        pdf.drawString(400,810, 'x400')
        pdf.drawString(500,810, 'x500')

        pdf.drawString(10,100, 'y100')
        pdf.drawString(10,200, 'y200')
        pdf.drawString(10,300, 'y300')
        pdf.drawString(10,400, 'y400')
        pdf.drawString(10,500, 'y500')
        pdf.drawString(10,600, 'y600')
        pdf.drawString(10,700, 'y700')
        pdf.drawString(10,800, 'y800')

    # ###################################
    # Content
    fileName = 'skin/report/ReportResultVisualisation.pdf'
    documentTitle = 'Bankruptcy Prediction Report'



    from reportlab.lib.units import mm


    # ###################################
    # 0) Create document
    from reportlab.pdfgen import canvas
    pdf = canvas.Canvas(fileName)
    pdf.setTitle(documentTitle)

    #drawMyRuler(pdf)
    # ###################################
    # 1) Title :: Set fonts
    # # Print available fonts
    # for font in pdf.getAvailableFonts():
    #     print(font)

    # Register a new font
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics


    pdf.setFont('Courier-Bold', 30)
    pdf.drawCentredString(300,500, 'Bankruptcy Prediction Result')
    pdf.drawCentredString(300, 470, 'Data Visulisation Report')
    pdf.setFont("Courier-Bold", 10)
    pdf.drawCentredString(290, 440, 'Created by Bankruptcy Prediction System')
    pdf.showPage()

    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')


    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageBnkResult13.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility moving toward bankruptcy?',
        '2) Which company have lowest possibility moving toward bankruptcy?',
        '3) Why you should not invest in this company?',
        '4) Are this company qualified to get loan?',
        '5) Why this company should file for bankruptcy?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Not Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageNotBnkResult13.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Not Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility result for not bankrupt?',
        '2) Which company have lowest possibility result for not bankrupt?',
        '3) Which company is the best company to make investment?',
        '4) Are this company qualified to get loan?',
        '5) Are the company in a good financial condition?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageResult13.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the comparison between bankrupt',
        'and not bankrupt prediction result of the companies.',
        '',
        'A stacked bar graph (or stacked bar chart) is a chart that uses bars to',
        'show comparisons between categories of data, but with ability to break ',
        'down and compare parts of a whole. Each bar in the chart represents a ',
        'whole, and segments in the bar represent different parts or categories ',
        'of that whole.'

    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageLineResult13.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above it show another type of graph which is line ',
        'graph that can be use to make the comparison between the possibility ',
        'of bankrupt and not bankrupt.',
        '',
        'A line chart or line plot or line graph or curve chart is a type of chart',
        'which displays information as a series of data points called markers',
        'connected by straight line segments.'
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)



    pdf.save()
    return send_file("report/ReportResultVisualisation.pdf", as_attachment=True)

@app.route("/downloadPDFOwn")
def downloadPDFOwn():
    def drawMyRuler(pdf):
        pdf.drawString(100,810, 'x100')
        pdf.drawString(200,810, 'x200')
        pdf.drawString(300,810, 'x300')
        pdf.drawString(400,810, 'x400')
        pdf.drawString(500,810, 'x500')

        pdf.drawString(10,100, 'y100')
        pdf.drawString(10,200, 'y200')
        pdf.drawString(10,300, 'y300')
        pdf.drawString(10,400, 'y400')
        pdf.drawString(10,500, 'y500')
        pdf.drawString(10,600, 'y600')
        pdf.drawString(10,700, 'y700')
        pdf.drawString(10,800, 'y800')

    # ###################################
    # Content
    fileName = 'skin/report/ReportResultVisualisation.pdf'
    documentTitle = 'Bankruptcy Prediction Report'



    from reportlab.lib.units import mm


    # ###################################
    # 0) Create document
    from reportlab.pdfgen import canvas
    pdf = canvas.Canvas(fileName)
    pdf.setTitle(documentTitle)

    #drawMyRuler(pdf)
    # ###################################
    # 1) Title :: Set fonts
    # # Print available fonts
    # for font in pdf.getAvailableFonts():
    #     print(font)

    # Register a new font
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfbase import pdfmetrics


    pdf.setFont('Courier-Bold', 30)
    pdf.drawCentredString(300,500, 'Bankruptcy Prediction Result')
    pdf.drawCentredString(300, 470, 'Data Visulisation Report')
    pdf.setFont("Courier-Bold", 10)
    pdf.drawCentredString(290, 440, 'Created by Bankruptcy Prediction System')
    pdf.showPage()

    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')


    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageBnkResultOwn.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility moving toward bankruptcy?',
        '2) Which company have lowest possibility moving toward bankruptcy?',
        '3) Why you should not invest in this company?',
        '4) Are this company qualified to get loan?',
        '5) Why this company should file for bankruptcy?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Possibility of Not Bankrupt')
    pdf.drawInlineImage('skin/static/images/imageNotBnkResultOwn.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the Possibility for Not Bankrupt',
        'Prediction Result of the companies.',
        '',
        'Suggested Question : ',
        '1) Which company have highest possibility result for not bankrupt?',
        '2) Which company have lowest possibility result for not bankrupt?',
        '3) Which company is the best company to make investment?',
        '4) Are this company qualified to get loan?',
        '5) Are the company in a good financial condition?',
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageResultOwn.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above you can analyzed the comparison between bankrupt',
        'and not bankrupt prediction result of the companies.',
        '',
        'A stacked bar graph (or stacked bar chart) is a chart that uses bars to',
        'show comparisons between categories of data, but with ability to break ',
        'down and compare parts of a whole. Each bar in the chart represents a ',
        'whole, and segments in the bar represent different parts or categories ',
        'of that whole.'

    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)

    pdf.showPage()
    #drawMyRuler(pdf)
    # ###################################
    # 2) Sub Title
    # RGB - Red Green and Blue
    pdf.setFont("Courier-Bold", 24)
    pdf.drawCentredString(290, 780, 'Prediction Result Visualization')

    # ###################################
    # 3) Draw a line
    pdf.line(30, 760, 550, 760)

    # ###################################
    # 4) Text object :: for large amounts of text
    from reportlab.lib import colors

    pdf.setFont("Courier-Bold", 15)
    pdf.drawCentredString(290, 720, 'Comparison Bankruptcy Prediction Result')
    pdf.drawInlineImage('skin/static/images/imageLineResultOwn.png', 40, 350, 180 * mm, 130 * mm)

    textLines = [
        'Base on the figure above it show another type of graph which is line ',
        'graph that can be use to make the comparison between the possibility ',
        'of bankrupt and not bankrupt.',
        '',
        'A line chart or line plot or line graph or curve chart is a type of chart',
        'which displays information as a series of data points called markers',
        'connected by straight line segments.'
    ]

    text = pdf.beginText(40, 330)
    text.setFont("Courier", 12)
    for line in textLines:
        text.textLine(line)
    pdf.drawText(text)



    pdf.save()
    return send_file("report/ReportResultVisualisation.pdf", as_attachment=True)

#### own model####
@app.route("/insertTraindata", methods=['GET','POST'])
def insertTraindata():
    return render_template("insertDataModel.html", title='HOME')

@app.route('/dataModel', methods=['GET', 'POST'])
def dataModel():
    if flask.request.method == 'GET':
        return (flask.render_template('insertDataModel.html'))

    if flask.request.method == 'POST':
        f = request.files['upload-file']
        filename = "dataModel.xlsx"
        f.save(os.path.join("skin\dataset", filename))
        success = "Successfully Insert Train Data"
        data = pd.read_excel(f)
        showdata = data.head()
        return render_template('insertDataModel.html', Success=success , showdata = showdata.to_html())

@app.route('/createModel', methods=['GET', 'POST'])
def createModel():
    dataModel = pd.read_excel(app.root_path+"\dataset\dataModel.xlsx")
    x = dataModel.drop('target', axis=1)
    y = dataModel['target']
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=0)

    print("Number transactions X_train64 dataset: ", x_train.shape)
    print("Number transactions y_train64 dataset: ", y_train.shape)
    print("Number transactions X_test64 dataset: ", x_test.shape)
    print("Number transactions y_test64 dataset: ", y_test.shape)

    from imblearn.over_sampling import SMOTE

    print("Before OverSampling, counts of label '1': {}".format(sum(y_train == 1)))
    print("Before OverSampling, counts of label '0': {} \n".format(sum(y_train == 0)))

    sm = SMOTE(random_state=2)
    x_train_res, y_train_res = sm.fit_sample(x_train, y_train.ravel())

    print('After OverSampling, the shape of train_X: {}'.format(x_train_res.shape))
    print('After OverSampling, the shape of train_y: {} \n'.format(y_train_res.shape))

    print("After OverSampling, counts of label '1': {}".format(sum(y_train_res == 1)))
    print("After OverSampling, counts of label '0': {}".format(sum(y_train_res == 0)))

    xtrain = x_train.shape
    ytrain = y_train.shape
    xtest = x_test.shape
    ytest = y_test.shape

    cntBfr1 = "Before OverSampling, counts of label '1': {}".format(sum(y_train == 1))
    cntBfr0 = "Before OverSampling, counts of label '0': {} \n".format(sum(y_train == 0))
    afteroverX = 'After OverSampling, the shape of train_X: {}'.format(x_train_res.shape)
    afteroverY = 'After OverSampling, the shape of train_y: {} \n'.format(y_train_res.shape)
    afterCnt1 = "After OverSampling, counts of label '1': {}".format(sum(y_train_res == 1))
    afterCnt0 = "After OverSampling, counts of label '0': {}".format(sum(y_train_res == 0))

    model = RandomForestClassifier(n_estimators=100)
    model.fit(x_train_res, y_train_res)


    test_accuracy = model.score(x_test, y_test)
    print("Accuracy: %.2f%%" % (test_accuracy * 100.0))

    testAcc = "Accuracy: %.2f%%" % (test_accuracy * 100.0)

    numLabels = len(dataModel.columns) - 1
    numTarget = 1

    from joblib import dump, load

    dump(model, app.root_path+"\model\BPSRFmodelUser.joblib")

    return render_template('dataModelInfo.html', xtrain=xtrain, ytrain=ytrain, xtest=xtest, ytest=ytest, cntBfr1=cntBfr1,
                           cntBfr0=cntBfr0, afteroverX=afteroverX, afteroverY=afteroverY, afterCnt1=afterCnt1, afterCnt0=afterCnt0,
                           testAcc=testAcc, numLabels=numLabels, numTarget=numTarget)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

