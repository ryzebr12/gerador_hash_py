import hashlib

def get_hash(algorithm, password):
    if algorithm == 'md5':
        hash_object = hashlib.md5()
    elif algorithm == 'sha512':
        hash_object = hashlib.sha512()
    elif algorithm == 'sha1':
        hash_object = hashlib.sha1()
    elif algorithm == 'sha2':
        hash_object = hashlib.sha256()
    else:
        print("Opção de hash inválida!")
        return None

    hash_object.update(password.encode('utf-8'))
    return hash_object.hexdigest()

def main():
    password = input("Digite a senha: ")

    print("Escolha o algoritmo de hash:")
    print("1. MD5")
    print("2. SHA-512")
    print("3. SHA-1")
    print("4. SHA-2 (SHA-256)")

    choice = input("Digite o número da opção desejada: ")

    if choice == '1':
        algorithm = 'md5'
    elif choice == '2':
        algorithm = 'sha512'
    elif choice == '3':
        algorithm = 'sha1'
    elif choice == '4':
        algorithm = 'sha2'
    else:
        print("Opção inválida!")
        return

    hashed_password = get_hash(algorithm, password)
    if hashed_password:
        print("Senha hash: " + hashed_password)

if __name__ == "__main__":
    main()
