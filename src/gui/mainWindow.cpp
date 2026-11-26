#include "mainWindow.h"
mainWindow::mainWindow(QWidget* parent)
    : QMainWindow(parent),encAlg(nullptr),fsw(nullptr) {
    ui.setupUi(this);  // Inicijalizacija UI-a

    this->setFixedSize(485, 345);

    connect(ui.pushButtonDT, &QPushButton::clicked, this, &mainWindow::onDtClicked);
    connect(ui.pushButtonA52, &QPushButton::clicked, this, &mainWindow::onA52Clicked);
    connect(ui.pushButtonCFB, &QPushButton::clicked, this, &mainWindow::onCfbClicked);
    connect(ui.buttonFSW, &QPushButton::clicked, this, &mainWindow::onFswClicked);
    connect(ui.buttonManual, &QPushButton::clicked, this, &mainWindow::onManualClicked);
    connect(ui.buttonSend, &QPushButton::clicked, this, &mainWindow::onSendClicked);
    connect(ui.buttonRecieve, &QPushButton::clicked, this, &mainWindow::onRecieveClicked);
    connect(ui.settingsButton, &QPushButton::clicked, this, &mainWindow::onSettingsClicked);

    ui.pushButtonDT->setEnabled(false);
    ui.pushButtonA52->setEnabled(false);
    ui.pushButtonCFB->setEnabled(false);

    ui.buttonFSW->setEnabled(false);
    ui.buttonManual->setEnabled(false);
    ui.buttonSend->setEnabled(false);
    ui.buttonRecieve->setEnabled(false);
}

mainWindow::~mainWindow() {}

void mainWindow::onDtClicked() {

    DtKeyDialog dtDialog(this);
    if (dtDialog.exec() != QDialog::Accepted)
        return;

    encAlg = new DoubleTranspositionCipher(dtDialog.getRowKey(), dtDialog.getColKey());
    fsw->setEncryptionStrategy(encAlg);

    ui.pushButtonDT->setEnabled(false);
    ui.pushButtonA52->setEnabled(true);
    ui.pushButtonCFB->setEnabled(true);

    ui.buttonFSW->setEnabled(true);
    ui.buttonManual->setEnabled(true);
    ui.buttonSend->setEnabled(true);
    ui.buttonRecieve->setEnabled(true);
   
}
void mainWindow::onA52Clicked() {
    A52KeyDialog a52Dialog(this);
    if (a52Dialog.exec() != QDialog::Accepted)
        return;

    encAlg = new A52Wrapper(a52Dialog.getKey(), a52Dialog.getFrame());
    fsw->setEncryptionStrategy(encAlg);
    
    ui.pushButtonA52->setEnabled(false);
    ui.pushButtonDT->setEnabled(true);
    ui.pushButtonCFB->setEnabled(true);

    ui.buttonManual->setEnabled(true);
    ui.buttonFSW->setEnabled(true);
    ui.buttonSend->setEnabled(true);
    ui.buttonRecieve->setEnabled(true);
}
void mainWindow::onCfbClicked() {
    CfbDialog cfbDialog(this);
    if (cfbDialog.exec() != QDialog::Accepted)
        return;

    word frame = cfbDialog.getFrame();
    uint8_t* key = cfbDialog.getKey();
    vector<uint8_t> iv = cfbDialog.getIv();
    A52 a52(key, frame);

    encAlg = new CFB(a52,iv,iv.size());
    fsw->setEncryptionStrategy(encAlg);

    ui.pushButtonCFB->setEnabled(false);
    ui.pushButtonDT->setEnabled(true);
    ui.pushButtonA52->setEnabled(true);

    ui.buttonManual->setEnabled(true);
    ui.buttonFSW->setEnabled(true);
    ui.buttonSend->setEnabled(true);
    ui.buttonRecieve->setEnabled(true);
}

void mainWindow::onFswClicked() {
    if (fsw->isRunning()) {
        fsw->stop();
        ui.buttonFSW->setText("Turn FSW on");
        ui.pushButtonDT->setEnabled(true);
        ui.pushButtonA52->setEnabled(true);
        ui.pushButtonCFB->setEnabled(true);
        ui.buttonManual->setEnabled(true);
        ui.buttonSend->setEnabled(true);
        ui.buttonRecieve->setEnabled(true);
        ui.settingsButton->setEnabled(true);
    }
    else {
        std::error_code ec;
        std::filesystem::create_directories(outputDir, ec);

        if (!std::filesystem::is_directory(targetDir, ec) ||
            !std::filesystem::is_directory(outputDir, ec)) {
            QMessageBox::warning(this, tr("FSW"),
                tr("Input or output folder does not exist."));
            return;
        }
        if (std::filesystem::equivalent(targetDir, outputDir, ec)) {
            QMessageBox::warning(this, tr("FSW"),
                tr("Input and output folders must be different."));
            return;
        }

        fsw->start();
        ui.buttonFSW->setText("Turn FSW off");
        ui.pushButtonDT->setEnabled(false);
        ui.pushButtonA52->setEnabled(false);
        ui.pushButtonCFB->setEnabled(false);
        ui.buttonManual->setEnabled(false);
        ui.buttonSend->setEnabled(false);
        ui.buttonRecieve->setEnabled(false);
        ui.settingsButton->setEnabled(false);
    }
}
void mainWindow::onManualClicked() {
    QString filename = QFileDialog::getOpenFileName(
        this,
        tr("Select file:"),
        "",
        tr("Text Files (*.txt)")
    );
    if (!filename.isEmpty()) {
        FileDialog* dialog = new FileDialog(filename,encAlg, this);
        dialog->exec();
    }
    else {
        qDebug() << "No file selected.";
    }
}
void mainWindow::onSendClicked() {

    QString filename = QFileDialog::getOpenFileName(
        this,
        tr("Select file:"),
        "",
        tr("Text Files (*.txt)")
    );

    if (filename.isEmpty()) {
        qDebug() << "No file selected.";
        return;
    }

    QFile file(filename);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        qDebug() << "Cannot open file.";
        return;
    }
    QTextStream in(&file);
    QString fileContent = in.readAll();
    file.close();

    QString justName = QFileInfo(filename).fileName();
    QString justName2 = filename.mid(filename.lastIndexOf('/') + 1);
    QByteArray nameBytes = justName2.toUtf8();
    std::string filenameStd(nameBytes.constData(), static_cast<size_t>(nameBytes.size()));

    std::string fileContentStd = fileContent.toUtf8().constData();

    std::string encryptedMsg = encAlg->encrypt(fileContentStd);   // 1. sifruj
    std::string msgHash = GetMD5String(encryptedMsg);        // 2. hash sifrata

    long fileSize = static_cast<long>(encryptedMsg.size());     // 3. velicina sifrata
    int  hashLength = static_cast<int>(msgHash.length());         // 4. duzina hasha (32)

    std::vector<std::byte> byteHash(hashLength);
    for (int i = 0; i < hashLength; i++)
        byteHash[i] = std::byte(msgHash[i]);

    initializeWSA();
    {
        Client client;                      
        client.ConnectToServer(12345);
        client.sendFileData(filenameStd, fileSize, hashLength, byteHash.data(), encryptedMsg);
    }
    cleanupWinsock();
}
void mainWindow::onRecieveClicked() {
    initializeWSA();
    Server server;
    server.BindSocket(12345);
    server.Listen();
    server.AcceptSocket();
    vector<string> fileContent = server.RecieveFileData();

    if (fileContent.size() < 2) {
        QMessageBox::warning(this, tr("Receive failed"),
            tr("File was not received correctly (connection error or hash mismatch)."));
        cleanupWinsock();
        return;
    }

    string fileName = fileContent[0];
    string encryptedMsg = fileContent[1];


    QString qFileName = QFileInfo(QString::fromStdString(fileName)).fileName();
    QSettings settings;
    QString qOutputDir = settings.value("outputDirectory", "").toString().trimmed();

    if (qOutputDir.isEmpty() || qFileName.isEmpty()) {
        QMessageBox::warning(this, tr("Cannot save file"),
            tr("Output folder or file name is empty. Open Settings, choose an output folder and click Save."));
        cleanupWinsock();
        return;
    }

    QDir dir(qOutputDir);
    QString outputFilePath = dir.filePath(qFileName);
    qDebug() << "Final outputFilePath:" << outputFilePath;

    cout << "Recieve file name: " << fileName << endl;
    cout << "Encrypted message: " << encryptedMsg << endl;

    string decryptedMsg = encAlg->decrypt(encryptedMsg);

    QFile file(outputFilePath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(decryptedMsg.data(), decryptedMsg.size());
        file.flush();
        file.close();
        cout << "File saved successfully!" << endl;
    }
    else {
        cerr << "Error: Could not open file for writing!" << endl;
    }
}
void mainWindow::onSettingsClicked() {
    SettingsWidget settingsDialog(this);
    settingsDialog.exec();

    QSettings settings;
    QString qTargetDir = settings.value("targetDirectory", "").toString().trimmed();
    QString qOutputDir = settings.value("outputDirectory", "").toString().trimmed();
    std::string stdTargetDir = qTargetDir.toUtf8().constData();
    std::string stdOutputDir = qOutputDir.toUtf8().constData();
    std::replace(stdTargetDir.begin(), stdTargetDir.end(), '/', '\\');
    std::replace(stdOutputDir.begin(), stdOutputDir.end(), '/', '\\');

    if (stdTargetDir.empty() || stdOutputDir.empty()) {
        QMessageBox::warning(this, tr("Settings"),
            tr("Choose both folders and click Save."));
        return;
    }

    this->targetDir = stdTargetDir;
    this->outputDir = stdOutputDir;

    delete fsw;
    fsw = new FileSystemWatcher(targetDir, outputDir);
    if (encAlg)
        fsw->setEncryptionStrategy(encAlg);

    ui.pushButtonDT->setEnabled(true);
    ui.pushButtonA52->setEnabled(true);
    ui.pushButtonCFB->setEnabled(true);
}
void mainWindow::initializeWSA() {
    WSADATA wsaData;
    int wsaerr;
    WORD wVersionRequested = MAKEWORD(2, 2);
    wsaerr = WSAStartup(wVersionRequested, &wsaData);
    if (wsaerr != 0) {
        std::cout << "Winsock dll not found.\n";
    }
    else {
        std::cout << "Winsock dll found!\n";
        std::cout << "Status: " << wsaData.szSystemStatus << std::endl;
    }
}
void mainWindow::cleanupWinsock() {
    WSACleanup();
}