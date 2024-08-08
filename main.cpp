#include <QApplication>
#include <QMainWindow>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include "SecureChatClient.h"
#include "AuthManager.h"

class ChatWindow : public QMainWindow {
    Q_OBJECT

public:
    ChatWindow(SecureChatClient* client, QWidget* parent = nullptr)
        : QMainWindow(parent), chatClient(client) {
        setWindowTitle("Secure Chat");

        QVBoxLayout* mainLayout = new QVBoxLayout;
        chatDisplay = new QTextEdit;
        chatDisplay->setReadOnly(true);

        QHBoxLayout* inputLayout = new QHBoxLayout;
        messageInput = new QLineEdit;
        QPushButton* sendButton = new QPushButton("Send");

        inputLayout->addWidget(messageInput);
        inputLayout->addWidget(sendButton);

        mainLayout->addWidget(chatDisplay);
        mainLayout->addLayout(inputLayout);

        QWidget* centralWidget = new QWidget;
        centralWidget->setLayout(mainLayout);
        setCentralWidget(centralWidget);

        connect(sendButton, &QPushButton::clicked, this, &ChatWindow::sendMessage);
    }

private slots:
    void sendMessage() {
        QString message = messageInput->text();
        if (!message.isEmpty()) {
            if (validateInput(message)) {
                chatClient->sendToServer(message.toStdString());
                messageInput->clear();
            } else {
                chatDisplay->append("Invalid input. Please enter a valid message.");
            }
        }
    }

private:
    bool validateInput(const QString& input) {
        return input.size() < 1024 && !input.contains(QRegExp("[<>]"));
    }

    SecureChatClient* chatClient;
    QTextEdit* chatDisplay;
    QLineEdit* messageInput;
};

int main(int argc, char* argv[]) {
    QApplication app(argc, argv);

    Aws::SDKOptions options;
    Aws::InitAPI(options);

    AuthManager authManager;
    if (!authManager.authenticateUser("username", "password")) {
        std::cerr << "Authentication failed." << std::endl;
        return 1;
    }

    SecureChatClient client("127.0.0.1", 12345);
    ChatWindow window(&client);
    window.show();

    int ret = app.exec();

    Aws::ShutdownAPI(options);

    return ret;
}
