from rake_nltk import Rake
import random
import os

def getKeywords(filename):
    # this function uses the rake library for extraction of the keywords
    # rake has a good performance and easy to use
    # spacy, yake, rake-nltk  are some of the libraries
    rake_nltk_var = Rake()
    file = open(filename, "r")
    text = file.read()
    rake_nltk_var.extract_keywords_from_text(text)
    keyword_extracted = rake_nltk_var.get_ranked_phrases()
    return keyword_extracted

def keygen(secpar):
    #secpar = security parameter
    #length of the key should be as long as secpar
    #secpar can be much long hence for loop is used
    key = ""
    for i in range(secpar):
        tmp = str(random.randint(0,1))
        key += tmp
    return key

def keygen2(secpar):
    return os.urandom(secpar)

def randomoracle(str):
    # random oracle is a true random hash function
    # for this implementation we are using hash we will be able to change it in future
    # as per wikipedia A system that is proven secure when every hash function is replaced by a random oracle is described as being secure in the random oracle model
    return hash(str)

def per(key, token):
    # pseudorandom permutation function
    # key = key, token = state token
    # the output will be next state token
    return "permuted value"

def iper(key, token):
    # pseudorandom permutation inverse
    # key = key, token =  state token
    # the output will be previous state token
    return "inverse permute"
