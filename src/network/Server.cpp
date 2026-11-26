#include "Server.h"
#include <cstring>

static bool recvAll(SOCKET s, char* buf, int len) {
	int total = 0;
	while (total < len) {
		int n = recv(s, buf + total, len - total, 0);
		if (n <= 0) return false; 
		total += n;
	}
	return true;
}

Server::Server() {
	serverSocket = INVALID_SOCKET;
	acceptSocket = INVALID_SOCKET;

	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serverSocket == INVALID_SOCKET) {
		cout << "Error at socket(): " << WSAGetLastError() << endl;
		WSACleanup();
	}
	else {
		cout << "server socket is OK." << endl;
	}
}

Server::~Server() {
	if (acceptSocket != INVALID_SOCKET) closesocket(acceptSocket);
	if (serverSocket != INVALID_SOCKET) closesocket(serverSocket);
}

void Server::BindSocket(int port) {
	sockaddr_in service;
	service.sin_family = AF_INET;
	InetPton(AF_INET, (L"127.0.0.1"), &service.sin_addr.s_addr);
	service.sin_port = htons(port);
	if (::bind(serverSocket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
		cout << "bind() failed: " << WSAGetLastError() << endl;
		closesocket(serverSocket);
		WSACleanup();
	}
	else {
		cout << "bind() is ok!" << endl;
	}
}
void Server::Listen() {
	if (listen(serverSocket, 1) == SOCKET_ERROR)
		cout << "listen(): Error listening on socket" << WSAGetLastError() << endl;
	else
		cout << "listen() is OK, waiting for connections" << endl;
}
void Server::AcceptSocket() {
	acceptSocket = INVALID_SOCKET;
	acceptSocket = accept(serverSocket, NULL, NULL);
	if (acceptSocket == INVALID_SOCKET) {
		cout << "accept failed: " << WSAGetLastError() << endl;
		WSACleanup();
	}
	else {
		cout << "Socked accepted!" << endl;
	}
}
void Server::Recieve() {
	char recieveBuffer[1000] = "";
	int byteCount = recv(acceptSocket, recieveBuffer, 1000, 0);
	if (byteCount < 0) {
		printf("Client:error %ld.\n", WSAGetLastError());
	}
	else
		printf("Received data: %s \n", recieveBuffer);
}
void Server::Send(string message) {
	const char* cMessage = message.c_str();
	int length = message.size();
	int byteCount = send(serverSocket, cMessage, length, 0);
	if (byteCount == SOCKET_ERROR) {
		printf("Server send error &ld.\n", WSAGetLastError());
	}
	else
		printf("Server: sent %ld bytes \n", byteCount);
}
vector<string> Server::RecieveFileData() {
	vector<string> err;

	// 1. ime fajla do '\n'
	string fileName;
	char ch;
	while (true) {
		if (!recvAll(acceptSocket, &ch, 1) || fileName.size() > 1024) {
			cout << "Failed to receive file name." << endl;
			return err;
		}
		if (ch == '\n') break;
		fileName += ch;
	}

	// 2. velicina sifrata (sa ogranicenjem od 100 MB)
	long fileSize = 0;
	if (!recvAll(acceptSocket, reinterpret_cast<char*>(&fileSize), sizeof(fileSize))
		|| fileSize < 0 || fileSize > 100L * 1024 * 1024) {
		cout << "Invalid file size." << endl;
		return err;
	}

	// 3. duzina hasha: MD5 u hex obliku je uvek 32 znaka
	int hashLength = 0;
	if (!recvAll(acceptSocket, reinterpret_cast<char*>(&hashLength), sizeof(hashLength))
		|| hashLength != 32) {
		cout << "Invalid hash length." << endl;
		return err;
	}

	// 4. hash
	vector<char> receivedHash(hashLength);
	if (!recvAll(acceptSocket, receivedHash.data(), hashLength)) return err;

	// 5. sifrat
	vector<char> encryptedBuffer(fileSize);
	if (!recvAll(acceptSocket, encryptedBuffer.data(), static_cast<int>(fileSize))) {
		cout << "Error while receiving encrypted data." << endl;
		return err;
	}
	string encryptedMsg(encryptedBuffer.begin(), encryptedBuffer.end());

	string computedHash = GetMD5String(encryptedMsg);
	if (computedHash.size() != static_cast<size_t>(hashLength)
		|| memcmp(computedHash.data(), receivedHash.data(), hashLength) != 0) {
		cout << "Hashes are different!" << endl;
		return err;
	}

	return { fileName, encryptedMsg };
}