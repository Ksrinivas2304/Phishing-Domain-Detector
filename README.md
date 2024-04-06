
# Phishing Domain Detection

A Full-Stack Machine Learning Project

## Objective

A phishing website is a common social engineering method that mimics trustful uniform resource locators (URLs) and webpages. The objective of this project is to train machine learning models and deep neural nets on the dataset created to predict phishing websites. Both phishing and benign URLs of websites are gathered to form a dataset and from them required URL and website content-based features are extracted. The performance level of each model is measures and compared.
## Data 

The set of phishing URLs are collected from opensource service called PhishTank. This service provide a set of phishing URLs in multiple formats like csv, json etc. that gets updated hourly. To download the data: https://www.phishtank.com/developer_info.php. From this dataset, 5000 random phishing URLs are collected to train the ML models.

The legitimate URLs are obatined from the open datasets of the University of New Brunswick, https://www.unb.ca/cic/datasets/url-2016.html. This dataset has a collection of benign, spam, phishing, malware & defacement URLs. Out of all these types, the benign url dataset is considered for this project. From this dataset, 5000 random legitimate URLs are collected to train the ML models.

All the data that we used in this project is stored in [data.csv](https://github.com/Ksrinivas2304/Phishing-Domain-Detector/blob/main/data.csv)
## Feature Extraction

The below mentioned category of features are extracted from the URL data:

1.Address Bar based Features
    -In this category 9 features are extracted.

2.Domain based Features
        -
    In this category 4 features are extracted.

3.HTML & Javascript based Features
        -
    In this category 4 features are extracted.

So, all together 17 features are extracted from the 10,000 URL dataset
## Models & Training

Before stating the ML model training, the data is split into 80-20 i.e., 8000 training samples & 2000 testing samples. From the dataset, it is clear that this is a supervised machine learning task. There are two major types of supervised machine learning problems, called classification and regression.

This data set comes under classification problem, as the input URL is classified as phishing (1) or legitimate (0). The supervised machine learning models (classification) considered to train the dataset in this project are:

1.Decision Tree

2.Random Forest

3.Multilayer Perceptrons

4.XGBoost

All these models are trained on the dataset and evaluation of the model is done with the test dataset [detection.ipynb](https://github.com/Ksrinivas2304/Phishing-Domain-Detector/blob/main/detection.ipynb)

## FrontEnd

To access this Phishing domain detection we created a user friendly website , in which we check that URL is Phishing or Legitimate.

Check the front end file [Templates](https://github.com/Ksrinivas2304/Phishing-Domain-Detector/blob/main/data.csv)
## Documentation

Refer this PPT to understand clearly 
[Presentation](https://github.com/Ksrinivas2304/Phishing-Domain-Detector/blob/main/Presentation.pptx)

## Output

From the obtained results of the above models, XGBoost Classifier has highest model performance of 92%. So the model is saved to the file [Model.pickle](https://github.com/Ksrinivas2304/Phishing-Domain-Detector/tree/main/Static/Models)
## Feature Idea

This project can be further extended to creation of browser extention or developed a GUI which takes the URL and predicts it's nature i.e., legitimate of phishing. As of now, I am working towards the creation of browser extention for this project. And may even try the GUI option also. 
