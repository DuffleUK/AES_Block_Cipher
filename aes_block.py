import key_schedule
import rijndael_consts

#---Normal round---
def aes_round(state_matrix, round_key, round_num):
    #Final container for end matrix
    final_state_matrix = [ [0] * 4 for _ in range(4)]
    
    for i in range(0,4):
        for j in range(0,4):
            # Remove the first two characters to get only the hex
            hex_num = state_matrix[i][j][2:].zfill(2)
            
            #---Begin Substitution Bytes---
            state_matrix[i][j] = state_matrix[i][j].zfill(2)
            state_matrix[i][j] = rijndael_consts.sbox[int(hex_num[0], 16)][int(hex_num[1], 16)]

    #---Shift rows---
    for i in range(1,4):
        for j in range(0,i):
            state_matrix[i].append(state_matrix[i][j])
        del state_matrix[i][:i]
    
    if round_num != 10:
        #---Mix Columns---
        for g in range(0,4):

            for h in range(0,4):
                
                overall = "0"
                
                for i in range(0,4):
                    #Multiply by 1 in field
                    if rijndael_consts.fixed_matrix[h][i] == "01":
                        total = bin(int(state_matrix[i][g],16))

                    #Multiply by 2 or 3
                    elif rijndael_consts.fixed_matrix[h][i] == "02" or rijndael_consts.fixed_matrix[h][i] == "03":
                        total = bin((int(state_matrix[i][g],16) << 1))

                        if rijndael_consts.fixed_matrix[h][i] == "03":
                            #Multiply by 3 in field
                            total = bin(int(total,2) ^ int(state_matrix[i][g],16))

                        #If primary digit is a 1
                        if int(state_matrix[i][g],16) > 127:
                            #XOR with hex 1B
                             total = bin(int(total,2) ^ int("1B",16))
                            
                    overall = bin(int(total,2)^int(overall,2))
                    result = hex(int(overall,2))

                #Format result
                if len(result) == 5:
                    result = result[3:]
                else:
                    result = result[2:]
                final_state_matrix[h][g] = result

    else:
        final_state_matrix = state_matrix

    #Perform XOR with round key
    for i in range(0,4):
        for j in range(0,4): 
            final_state_matrix[i][j] = hex(int(final_state_matrix[i][j], 16) ^ int(round_key[i][j], 16))

    return final_state_matrix

def block_encrypt(state_matrix, cipher_key):
    round_keys = key_schedule.get_round_keys(cipher_key)

    #---First round---
    #Perform XOR with round key 0
    for i in range(0,4):
        for j in range(0,4): 
            state_matrix[i][j] = hex(int(state_matrix[i][j], 16) ^ int(round_keys[0][i][j], 16))

    previous = state_matrix
    for i in range(1,11):
        previous = aes_round(previous, round_keys[i], i)
        if i == 10:
            return key_schedule.restructure_keys(previous)

input_plaintext = [
    ["54", "4f", "4e", "20"],
    ["77", "6e", "69", "54"],
    ["6f", "65", "6e", "77"],
    ["20", "20", "65", "6f"]
    ]

cipher_key = [
    ["54", "73", "20", "67"],
    ["68", "20", "4b", "20"],
    ["61", "6d", "75", "46"],
    ["74", "79", "6e", "75"]
    ]

print(block_encrypt(input_plaintext, cipher_key))
