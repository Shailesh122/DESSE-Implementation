from aesdet import AESDet as PRF
from helpers import keygen2

class StateNode:
    def __init__(self,counter,statetoken):
        self.counter = counter
        self.statetoken = statetoken

class DESSEClient:

    def __init__(self, secpar):
        self.secpar = secpar # security parameter
        self.keywordmap = {} #map of the keywords present
        #key : keyword value: (state token, counter variable)

    def getNewKey(self):
        #return the random bytes of length secpar
        return os.urandom(self.secpar)

    def getStateToken(self,keyword):
        if keyword in self.keywordmap.keys():
            return self.keywordmap[keyword]
        else:
            return ""

    def addToMap(self,counter,statetoken,keyword):
        # this method will add the curent token to keyword map
        self.keywordmap[keyword] = StateNode(counter,statetoken)

    def permute(self,key, curr):
        #permute the next token and return it
        tok = key^curr
        return tok

    def getNextToken(self,keyword):
        # create a next token and update it in the keyword map
        key = self.getNewKey()
        curr = self.getStateToken(keyword)
        newtoken = self.permute(key,curr.statetoken)
        self.addToMap(self,curr.counter+1,newtoken,keyword)
