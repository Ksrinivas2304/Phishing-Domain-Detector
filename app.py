#!/usr/bin/env python
# coding: utf-8

# In[1]:





# In[2]:


from flask import Flask, request, jsonify,render_template
import pickle
import xgboost

from flask import Flask

app = Flask(__name__, static_url_path='/static')


# Load your trained model
with open('Static/Models/model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

@app.route('/About', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/What we do', methods=['POST'])
def do():
    return render_template('do.html')

@app.route('/Add URL', methods=['GET','POST'])
def addURL():
    return render_template('addURL.html')

@app.route('/Contact us', methods=['GET','POST'])
def contact():
    return render_template('contact.html')

def classify_url():
    try:
        # Get the URL from the request
        url = request.json['url']

        # Perform classification using your model
        prediction = model.predict([url])

        # Return the classification result
        result = "Phishing" if prediction[0] == 1 else "Legitimate"
        return jsonify({'result': result})

    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)

