import rijndael_consts

#Obselete but used to generate the round keys used below
def get_round_consts():
    #Calculate the round constants needed for AES
    rcon_list = []
    for i in range(0,20):
        if i == 0:
            rcon_list.append(1)
        elif rcon_list[i-1] < int("80", 16):
            rcon_list.append(int(bin(rcon_list[i-1] << 1),2))
        else:
            temp = int(bin((rcon_list[i-1] << 1) ^ int("1B",16)),2)
            #If primary digit is a 1, ignore the first hexadecimal digit
            if temp > 127:
                temp = int(str(hex(temp))[3:],16)
            rcon_list.append(temp)
    return rcon_list

#List of round keys
rcon_list = ["01","02","04","08","10","20","40","80","1B","36"]

#Restructures lists for easier editing
def restructure_keys(round_key):
    #Flip array so it is properly structured into words
    new_round_key = []
    for i in range(0,4):
        new_round_key.append([])
    for i in range(0,4):
        for j in range(0,4):
            new_round_key[j].append(round_key[i][j])
    return new_round_key

#Gets the first word of a round key
def get_first_word(input_key, round_num):
    input_key_copy = []
    for key in input_key:
        input_key_copy.append(key.copy())
    input_key = input_key_copy
    #Circular byte left shift of last word
    word = input_key[3]
    word.append(word[0])
    del word[0]
    input_key[3] = word
    #Substitute all values in the key
    for i in range(0,4):
        for j in range(0,4):
            input_key[i][j] = input_key[i][j].zfill(2)
            input_key[i][j] = rijndael_consts.sbox[int(input_key[i][j][0],16)][int(input_key[i][j][1],16)]
    #Find round constant for given round
    rcon = rcon_list[round_num-1]
    #Add round constant to the last word
    input_key[-1][0] = str(hex(int(bin(int(input_key[3][0],16) ^ int(rcon,16)),2)))[2:]
    input_key[-1][0] = input_key[-1][0].zfill(2)
    return input_key

#Generate first word for expanding the key
def generate_words(original_key, new_key):
    first_word = []
    for i in range(0,4):
        value = str(hex(int(bin(int(new_key[3][i],16) ^ int(original_key[0][i],16)),2)))[2:]
        value = value.zfill(2)
        first_word.append(value)
    original_key.append(first_word)
    for i in range(1,4):
        new_word = []
        for j in range(0,4):
            #XOR each value in the original key with the new key
            value_to_append = str(hex(int(bin(int(original_key[i][j],16) ^ int(original_key[i+3][j],16)),2)))[2:]
            value_to_append = value_to_append.zfill(2)
            new_word.append(value_to_append)
        original_key.append(new_word)
    return original_key[-4:]

#Overall function that expands the key
def get_round_keys(round_key):
    #Restructure the input key so the columns are now rows
    new_key = restructure_keys(round_key)

    #Create the array that the program will output and fill in initial cipher key
    output_keys = []
    output_keys.append(round_key)
    #Create all required round keys
    for i in range(1,11):
        #Get the first word then generate the next 3
        temp_key = get_first_word(new_key, i)
        next_key = generate_words(new_key, temp_key)
        #Assing the next key as the new key for the next iteration
        new_key = next_key
        #Restructure to suit the block encryption and append it to output
        output_key = restructure_keys(new_key)
        output_keys.append(output_key)
    #Return the array of keys
    return output_keys
    
