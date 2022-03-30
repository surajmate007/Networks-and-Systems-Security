# Write your script here
from os import remove
from typing import Sized

class crptAnalysis():
    def __init__(self, ciphertext):
        self.ciphertext = ciphertext

    def freqAnalysis(self, ciphertext, alphabetMappings):
        newCipher = ciphertext.replace(' ', '')
        newCipher = newCipher.replace(',', '')
        newCipher = newCipher.replace('.', '')
        newCipher = newCipher.replace(';', '')
        newCipher = newCipher.replace('!', '')

        p=0
        mpp4 = dict()
        while(p+4 < len(ciphertext)):
            quad = ""
            for i in range(p, p+4):
                if(ciphertext[i]==' ' or ciphertext[i]==',' or ciphertext[i]=='.' or ciphertext[i]==';' or ciphertext[i]=='!'):
                    continue
                else:
                    quad += ciphertext[i]
                if(len(quad) == 4):
                    if(quad in mpp4):
                        mpp4[quad] += 1
                    else:
                        if(ciphertext[p-1]==' ' and ciphertext[p+4]==' '):
                            mpp4[quad] = 1
            p+=1
        mpp4 = sorted(mpp4.items(), key=lambda x : x[1], reverse=True)

        p=0
        mpp3 = dict() 
        # mpp3 is the customised data storage where the first element is the string , second is its frequency and third is whether it is suffix(0) or not(1).
        while(p+3 < len(ciphertext)):
            trip = ""
            for i in range(p, p+3):
                if(ciphertext[i]==' ' or ciphertext[i]==',' or ciphertext[i]=='.' or ciphertext[i]==';' or ciphertext[i]=='!'):
                    continue
                else:
                    trip += ciphertext[i]
            if(len(trip) == 3):    
                if(trip in mpp3):
                    if(ciphertext[p+3]==' ' and ciphertext[p-1]==' '):
                        mpp3[trip][0] += 1
                    elif(ciphertext[p+3]==' ' and ciphertext[p-1]!=' '):
                        mpp3[trip][0] += 1    
                else:
                    if(ciphertext[p+3]==' ' and ciphertext[p-1]==' '):
                        mpp3[trip] = [1, 1]
                    elif(ciphertext[p+3]==' ' and ciphertext[p-1]!=' '):
                        mpp3[trip] = [1, 0]    
            p+=1
        mpp3 = sorted(mpp3.items(), key=lambda x : x[1][0], reverse=True)

        p=0
        mpp2 = dict()
        while(p+2 < len(newCipher)):
            dup = newCipher[p : p+2]
            if(dup in mpp2):
                mpp2[dup] += 1
            else:
                mpp2[dup] = 1
            p+=1
        mpp2 = sorted(mpp2.items(), key=lambda x : x[1], reverse=True)

        p=0
        mpp1 = dict()
        while(p < len(newCipher)):
            ch = newCipher[p]
            if(ch in mpp1):
                mpp1[ch] += 1
            else:
                mpp1[ch] = 1
            p+=1
        mpp1 = sorted(mpp1.items(), key=lambda x : x[1], reverse=True)
        ans = newCipher
        ans = self.replacement(ans, mpp1, mpp2, mpp3, mpp4, alphabetMappings)
        ans = self.finalAns(ans, ciphertext)
        return ans


    def getKey(self, ciphertext, alphabetMappings, cipherChars):
        ans = self.freqAnalysis(ciphertext, alphabetMappings)
        notMapped = []
        for i in range(len(cipherChars)):
            char = cipherChars[i]
            if(char not in alphabetMappings):
                notMapped.append(char)

        p=0
        for j in range(len(alphabetMappings)):
            if(alphabetMappings[j] == None):
                alphabetMappings[j] = notMapped[p]
                p+=1

        key = ""
        for i in range(len(alphabetMappings)):
            key += alphabetMappings[i]
        return key


    def replacement(self, ans, mpp1, mpp2, mpp3, mpp4, alphabetMappings):
            # we are considering of replacing of only three triplets (AND, THE, ING)

        rank1 = ["E", "T", "A", "O", "I", "N", "S", "H", "R", "D", "U", "L", "C", "B", "W", "F", "G", "V", "P", "M", "Y", "J",
                "K", "X", "Q", "Z"]                               # Most frequent Characters

        rank2 = ["TH", "HE", "IN", "AN", "RE", "ON", "ES", "ED", "ST", "EN", "AT", "TO", "NT", "HA", "ND", "OU", "EA", "NG", "AS", "OR", "TI", "IS", "ET", "IT", "AR", "TE", "SE", "HI", "OF", "ER", "AL", "DE",
                "LU", "LO", "LI", "LE", "LA", "AL", "EL", "IL", "OL", "SA", "SI", "AR", "VE", "RA", "LD", "UR", "WE", "WA", "WI", "WO", "AW", "SW", "OW", "GA", "GE", "GR", "GO", "GU", "AG", "EG", "IG", "OG",
                "VA", "VO", "VE", "AV", "EV", "OV", "IV", "PA", "PE", "PI", "PL", "PR", "PO", "AP", "EP", "OP", "SP", "UP", "MA", "ME", "MO", "MU", "MI", "AM", "IM", "EM", "OM", "SM", "UM", "YE", "TO",
                "YA", "BY", "EY", "MY", "PY", "TY", "JA", "JI", "JE", "JO", "JU", "AJ", "KE", "KI", "KA", "AK", "OK" , "SK", "BO", "BA", "BR", "BE", "BI", "BU", "BL", "AB", "EB", "IB", "OB", "UB", "FU", "FR", "FA",
                "FI", "FO" "FL", "FE", "AF", "EF", "IF", "OF", "UF", "EX", "AX", "OX", "YA", "YI", "ZE", "ZO", "OZ"]   # Most frequent duplets

        rank3 = ["THE", "AND"]                                    # Most frequent triplets

        rank4 = ["THAT", "THIS"]                                  # Most frequent quads 

        replaced = ""
        run = 0
        notQuad = 0
        quad = mpp4[0][0]
        if(mpp3[0][0] not in quad and mpp3[1][0] not in quad):
            if(quad[0] == quad[3]):
                ans = self.replaceGrp(ans, quad, rank4[0], alphabetMappings)
                replaced += quad
            elif(quad[0] != quad[1] and quad[2] != quad[3] and quad[1] != quad[3] and quad[1] != quad[2]):
                ans = self.replaceGrp(ans, quad, rank4[1], alphabetMappings)
                replaced += quad

        ans = self.mapDuplets(mpp2, rank2, ans, replaced, alphabetMappings)

        for i in range(2):
            if((mpp3[i][1][0] / len(mpp3)) > 0.20 or replaced == ""):
                run+=1
        p=0
        for i in range(run):
            if(mpp3[i][0][0] != mpp3[i][0][1] and mpp3[i][0][1] != mpp3[i][0][2] and mpp3[i][0][0] != mpp3[i][0][2]):
                if(mpp3[i][1][1] == 1):
                    # means the triplet is independent like (AND , THE)
                    ans = self.replaceGrp(ans, mpp3[i][0], rank3[p], alphabetMappings)
                    replaced += mpp3[i][0]
                    p+=1
                else:
                    # means the triplet is suffix like (ING, HER)
                    ans = self.replaceGrp(ans, mpp3[i][0], "ING", alphabetMappings)
                    replaced += mpp3[i][0]

                ans = self.mapDuplets(mpp2, rank2, ans, replaced, alphabetMappings)
        
        ans = self.mapDuplets(mpp2, rank2, ans, replaced, alphabetMappings)
        
        for i in range(30):
            if(i < len(mpp1) and len(rank1) != 0):
                if(mpp1[i][0] not in alphabetMappings):
                    ans = ans.replace(mpp1[i][0], rank1[0])
                    alphabetMappings[ord(rank1[0])-65] = mpp1[i][0]
                    replaced += mpp1[i][0]
            rank1 = self.updateRank1(rank1, alphabetMappings) 
            ans = self.mapDuplets(mpp2, rank2, ans, replaced, alphabetMappings)    # Everytime calling map duplets
        return ans


    def mapDuplets(self, mpp2, rank2, ans, replaced, alphabetMappings):
        if(len(rank2) == 0):
            return ans

        for i in range(6):
            if(i < len(mpp2)):
                if(mpp2[i][0][0] not in alphabetMappings or mpp2[i][0][1] not in alphabetMappings):
                    index = -1
                    char = ''
                    for j in range(2):
                        if(mpp2[i][0][j] in alphabetMappings):
                            index = j
                            char = chr(alphabetMappings.index(mpp2[i][0][j]) + 65)
                    if(index == 0):
                        for k in range(len(rank2)):
                            if(rank2[k][0] == char):
                                ans = self.replaceGrp(ans, mpp2[i][0][1], rank2[k][1], alphabetMappings)
                                replaced += mpp2[i][0][1]
                                break
                        
                    elif(index == 1):
                        for k in range(len(rank2)):
                            if(rank2[k][1] == char):
                                ans = self.replaceGrp(ans, mpp2[i][0][0], rank2[k][0], alphabetMappings)
                                replaced += mpp2[i][0][0]
                                break
                    else:
                        pass
                rank2 = self.updateRank2(rank2, alphabetMappings)
        return ans


    def updateRank2(self, rank2, alphaMappings):
        for i in range(len(rank2)):
            if(i < len(rank2)):
                dup = rank2[i]
                if(alphaMappings[ord(dup[0])-65] != None and alphaMappings[ord(dup[1])-65] != None):
                    rank2.remove(dup)
            else:
                pass
        return rank2


    def updateRank1(self, rank1, alphaMappings):
        for i in range(len(rank1)):
            if(i < len(rank1)):
                char = rank1[i]
                if(alphaMappings[ord(char) - 65] != None):
                    rank1.remove(char)
            else:
                pass
        return rank1


    def replaceGrp(self, ans, trip, repl, alphabetMappings):
        for i in range (len(repl)):
            if(alphabetMappings[ord(repl[i]) - 65] == None):
                ans = ans.replace(trip[i], repl[i])
                alphabetMappings[ord(repl[i]) - 65] = trip[i]
        return ans


    def finalAns(self, ans, ciphertext):
        fans = ""
        n = len(ciphertext)
        p=0
        for i in range(n):
            if(ciphertext[i] == ' ' or ciphertext[i] == ',' or ciphertext[i] == '.' or ciphertext[i]==';' or ciphertext[i]=='!'):
                fans += ciphertext[i]
                p+=1
            else:
                fans += ans[i-p]
        return fans
        

class DecipherText(object): # Do not change this
    def decipher(self, ciphertext): # Do not change this
        """Decipher the given ciphertext"""

        # Write your script here

        alphabetMappings = [None for i in range (26)]
        cipherChars = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "@", "#", "$", "z", "y", "x", "w", "v", "u", "t", "s", "r", "q", "p", "o", "n"]
        ans = crptAnalysis(ciphertext)
        deciphered_text = ans.freqAnalysis(ciphertext, alphabetMappings)
        deciphered_key = ans.getKey(ciphertext, alphabetMappings, cipherChars)

        print("Ciphertext: " + ciphertext) # Do not change this
        print("Deciphered Plaintext: " + deciphered_text) # Do not change this
        print("Deciphered Key: " + deciphered_key) # Do not change this

        return deciphered_text, deciphered_key # Do not change this

if __name__ == '__main__': # Do not change this
    DecipherText() # Do not change this

