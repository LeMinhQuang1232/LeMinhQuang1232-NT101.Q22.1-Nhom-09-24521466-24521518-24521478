import math
import base64

def Euclid_mo_rong(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = Euclid_mo_rong(b % a, a)
    return gcd, y1 - (b // a) * x1, x1

def inverse_mod(e, phi_n):
    gcd, x, _ = Euclid_mo_rong(e, phi_n)
    if gcd != 1:
        return None
    return x % phi_n
#Tao khoa RSA
def create_key (p, q, e):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    print("phi_n: ", phi_n)
    d = inverse_mod(e, phi_n)
    if d is None:
        raise Exception("e không hợp lệ (không có nghịch đảo mod phi)")

    return (e, n), (d, n)

#---mã hóa
#mã hóa cho tính bảo mật: M ^ e mod n
def en_EFC(M, pub):
    e, n = pub
    return pow(M, e, n)
#mã hóa cho tính xác thực: M ^ d mod n
def en_EFA(M, pri):
    d, n = pri
    return pow(M, d, n)
#---giải mã
#giải mã cho tính bảo mật: C ^ d mod n
def de_EFC(C, pri):
    d, n = pri
    return pow(C, d, n);
#giải mã cho tính xác thực: C ^ e mod n
def de_EFA(C, pub):
    e, n = pub
    return pow(C, e, n)
#base64-câu 3:
def encrypt_string(msg, pub):
    e, n = pub
    cipher_list = [pow(ord(ch), e, n) for ch in msg]
    data = " ".join(map(str, cipher_list)).encode()
    return base64.b64encode(data).decode()
#
def decrypt_string(cipher_b64, priv):
    d, n = priv
    data = base64.b64decode(cipher_b64).decode()
    cipher_list = list(map(int, data.split()))
    return "".join(chr(pow(c, d, n)) for c in cipher_list)

#--cau 4 --
def decrypt_base64_hex_binary(C, pri, info=""):
    d, n = pri
    # C < n vì C = M^e mod n
    if C >= n:
        print(f"[{info}] Bỏ qua (C >= n)")
        return
        
    M = pow(C, d, n)
    try:
        # chuyển số về bytes
        length = max(1, (M.bit_length() + 7) // 8)
        my_bytes = M.to_bytes(length, byteorder='big')

        # giải mã utf-8
        plaintext = my_bytes.decode('utf-8')

        # kiểm tra xem text có hợp lệ không
        if plaintext.isprintable():
            print(f"[{info}] => {plaintext}")
        else:
            print(f"[{info}] => (không phải text printable)")

    except UnicodeDecodeError:
        print(f"[{info}] => Không decode được (có thể sai khóa)")
    
#main
if __name__== "__main__":
    tmp = int(input("Vui long nhap loai thap phan (0) hay thap luc phan (1): "))
    if tmp == 0:
        p = int(input("Nhap so p: "))
        q = int(input("Nhap so q: "))
        e = int(input("Nhap so e: "))
    else:
        p = int(input("Nhap so p: "), 16)
        q = int(input("Nhap so q: "), 16)
        e = int(input("Nhap so e: "), 16)
    pub, pri = create_key(p, q, e)
    print("Khoa cong khai va bi mat: ")
    print("- Khoa bi mat: ", pri)
    print("- Khoa cong khai: ", pub)
    M = 5
    efc = en_EFC(M, pub)
    efa = en_EFA(M, pri)
    print("---MA HOA---")
    print("Ma hoa cho tinh bao mat: ", efc)
    print("Ma hoa cho tinh xac thuc: ", efa)
    print("---GIAI MA---")
    plaintext1 = de_EFC(efc, pri)
    plaintext2 = de_EFA(efa, pub)
    print("Giai ma cho tinh bao mat: ", plaintext1)
    print("Giai ma cho tinh xac thuc: ", plaintext2)

    #cau 3

    message = "The University of Information Technology"
    en_message = encrypt_string(message, pub)
    print("---Cau 3---")
    print("Chuoi sau khi ma hoa la: ", en_message)

    #cau 4

    print("\n---Cau 4---")
    #pub1 = (7, 187)
    pri1 = (23, 187)
    #pub2 = (17, 6136901602090281288655069647627226674348541791)
    pri2 = (2887953695101308841719959028992297701642456369, 6136901602090281288655069647627226674348541791)
    #pub3 = (886979, 101776877529005912638346811918779931246783058062684819617574643018368103302097)
    pri3 = (24212225287904763939160097464943268930139828978795606022583874367720623008491, 101776877529005912638346811918779931246783058062684819617574643018368103302097)
    
    private_keys = {
        "Key 1": pri1,
        "Key 2": pri2,
        "Key 3": pri3
    }

    # cipher ma de cho
    cipher1 = "raUcesUlOkx/8ZhgodMoo0Uu18sC20yXlQFevSu7W/FDxIy0YRHMyXcHdD9PBvIT2aUft5fCQEGomiVVPv4I"
    cipher2 = "C87F570FC4F699CEC24020C6F54221ABAB2CE0C3"
    cipher3 = "Z2BUSkJcg0w4XEpgm0JcMExEQmBlVH6dYEpNTHpMHptMQ7NgTHlgQrNMQ2BKTQ=="
    cipher4 = "001010000001010011111111101101110010111011001010111011000110011110111111001111110110100011001111001100001001010001010100111101010100110011101110111011110101101100000100"

    data1 = base64.b64decode(cipher1)
    data3 = base64.b64decode(cipher3)

    n1 = int.from_bytes(data1, "big")
    n2 = int(cipher2, 16)
    n3 = int.from_bytes(data3, "big")
    n4 = int(cipher4, 2)
    
    ciphertexts = {
        "Cipher 1": n1,
        "Cipher 2": n2,
        "Cipher 3": n3,
        "Cipher 4": n4
    }
    for c_name, c_val in ciphertexts.items():
        for k_name, k_val in private_keys.items():
            decrypt_base64_hex_binary(c_val, k_val, f"Giải mã {c_name} bằng {k_name}")

