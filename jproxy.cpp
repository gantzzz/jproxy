#include <iostream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <thread>
#include <unistd.h>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <mutex>

using namespace std;
using json = nlohmann::json;

// Callback function to handle data received from the server
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb;
    userp->append((char*)contents, totalSize);
    return totalSize;
}

static int m_nPort = 8810;
static bool m_bRunning = true;
static string ACTION_CONNECT = "action:connect";
static CURL* curl = curl_easy_init();
static vector<string> locations;
static vector<thread*> threads;
static mutex Mutex;

void cleanup_thread(std::thread::id id)
{
    lock_guard<mutex> lock(Mutex);
    thread* remove_thread;
    for ( auto th : threads )
    {
        if ( th->get_id() == this_thread::get_id() )
        {
            remove_thread = th;
            break;
        }
    }

    auto new_end = std::remove_if(threads.begin(), threads.end(), []( const std::thread* th)
    {
        return th->get_id() == std::this_thread::get_id();
    });

    threads.erase(new_end, threads.end());
    remove_thread->detach();

    delete remove_thread;
}

string resolve_host(string host)
{
    // Resolving hostname to IP address
    struct addrinfo *result;
    int status = getaddrinfo(host.c_str(), NULL, NULL, &result);
    // Extracting the IP address from the result
    struct sockaddr_in *addr = (struct sockaddr_in *)(result->ai_addr);
    if (status != 0)
    {
        cout << "error occured while resolving host: " << host << endl;
        cleanup_thread(this_thread::get_id());
        return "";
    }
    char ip_address[INET_ADDRSTRLEN]; // Buffer to store the IP address string
    inet_ntop(AF_INET, &(addr->sin_addr), ip_address, INET_ADDRSTRLEN);
    freeaddrinfo(result);
    return string(ip_address);
}

void ProxyClient(int client, char* data, size_t data_len,string location)
{
    string forward_server;
    for ( auto loc : locations )
    {
        if (location == loc)
        {
            std::ostringstream oss;
            oss << location << "-justvpn-server-service";
            forward_server = oss.str();

            break;
        }
    }
    cout << "target service is: " << forward_server << endl;

    // setup forward server
    int forwardSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (forwardSocket == -1)
    {
        std::cerr << "Error: Failed to create socket for forwarding: " << strerror(errno) << endl;
        cleanup_thread(this_thread::get_id());
        return;
    }

    auto resolved_host = resolve_host(forward_server);

    // Define address structure for target server
    struct sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr.s_addr = inet_addr(resolved_host.c_str());
    targetAddr.sin_port = htons(8811);

    // Connect socket to target server
    if (connect(forwardSocket, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) == -1)
    {
        std::cerr << "Error: Failed to connect to target server: " << strerror(errno) << endl;
        close(forwardSocket);
        cleanup_thread(this_thread::get_id());
        return;
    }

    // Send original data to target server
    send(forwardSocket, data, data_len, 0);

    char buffer[4096];
    /*while (true)
    {
        // Receive response from target server
        ssize_t bytesReceived = recv(forwardSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived == 0) {
            // Remote party closed the connection
            std::cout << "Remote party closed the connection\n";
            break;
        } else if (bytesReceived < 0) {
            // Error occurred
            cout << "Error: Failed to receive data from target server: " << strerror(errno) << endl;
            break;
        }
// debug
        std::string str(buffer + 1, bytesReceived);
        cout << "received from the client: " << str << endl;
// debug(end)

        // Send response back to client
        send(client, buffer, bytesReceived, 0);

        // receive from client
        bytesReceived = recv(client, buffer, sizeof(buffer), 0);
        if (bytesReceived == 0) {
            // Remote party closed the connection
            std::cout << "Remote party closed the connection\n";
            break;
        } else if (bytesReceived < 0) {
            // Error occurred
            cout << "Error: Failed to receive data from target server: " << strerror(errno) << endl;
            break;
        }

        // send to the server
        send(forwardSocket, buffer, bytesReceived, 0);
    }*/






    size_t timeoutsCounter = 0;
    unsigned char packet[1400] = { 0 };

    int length = 0;

    fd_set fdset;
    struct timeval timeout;

    while (m_bRunning)
    {
        FD_ZERO(&fdset);
        FD_SET(forwardSocket, &fdset);
        FD_SET(client, &fdset);

        memset(&timeout, 0, sizeof(struct timeval));
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        // Find the highest file descriptor
        int nfds = std::max(forwardSocket, client) + 1;

        int retval = select(nfds, &fdset, NULL, NULL, &timeout);

        if (retval > 0)
        {
            if (FD_ISSET(forwardSocket, &fdset))
            {
                length = recv(forwardSocket, packet, sizeof(packet), 0);

                if (length > 0)
                {
                    send(client, packet, length, 0);
                }
            }
            
            if (FD_ISSET(client, &fdset))
            {
                length = recv(client, packet, sizeof(packet), 0);

                if (length > 0)
                {
                    send(forwardSocket, packet, length, 0);
                }
            }
        }
        else if (retval == 0) // timeout
        {
            timeoutsCounter++;
        }

        if (timeoutsCounter >= 15) // 30 seconds
        {
            break; // connection is probably killed, exit the loop
        }
    }











    // Close sockets
    close(client);
    close(forwardSocket);

    cleanup_thread(this_thread::get_id());
}

void getServers()
{
    if(curl)
    {
        // URL to fetch
        const std::string url = "http://justvpn.online/api/getservers";
        std::string readBuffer;

        // Set CURL options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // Perform the request
        CURLcode res = curl_easy_perform(curl);

        // Check for errors
        if(res != CURLE_OK)
        {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        json j = json::parse(readBuffer);

        if (j.is_array())
        {
            // Iterate over each object in the array
            for (const auto& obj : j)
            {
                // Check if the object has the "country" field
                if (obj.contains("country")) {
                    // Get the value of the "country" field
                    std::string country = obj["country"].get<std::string>();

                    locations.push_back(country);
                }
            }
        }
    }
}

int main (int argc, char** argv)
{
    bool bBind = true;
    int client = socket(AF_INET6, SOCK_DGRAM, 0);

    getServers();

    while (m_bRunning)
    {
        char packet[1500];

        sockaddr_in6 addr;
        socklen_t addrlen = sizeof(addr);

        memset(&addr, 0, addrlen);
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(m_nPort);

        // bind to a sever port
        // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
        if (bBind)
        {
            client = socket(AF_INET6, SOCK_DGRAM, 0);

            // use an IPv6 socket to cover both IPv4 and IPv6.
            int flag = 1;
            int nSockOptResult = -1;

            nSockOptResult = setsockopt(client, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

            flag = 0;
            nSockOptResult = setsockopt(client, IPPROTO_IPV6, IPV6_V6ONLY, &flag, sizeof(flag));

            memset(&addr, 0, addrlen);
            addr.sin6_family = AF_INET6;
            addr.sin6_port = htons(m_nPort);

            while (::bind(client, (sockaddr *)&addr, addrlen))
            {
                if (errno != EADDRINUSE)
                {
                    cout << "Error in bind" << endl;
                    exit(1);
                }

                this_thread::sleep_for(chrono::milliseconds(100));
            }

            bBind = false;
        }

        // timeout to check whether the server is shutting down
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;

        if (setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0)
        {
            close(client);
            bBind = true;
            continue;
        }

        int n = recvfrom(client, packet, sizeof(packet), 0, (sockaddr *)&addr, &addrlen);

        if (n <= 0)
        {
            if (errno != EAGAIN &&
                errno != EWOULDBLOCK)
            {
                bBind = true;
                close(client);
            }

            cout << "running proxy threads: " << threads.size() << endl;

            continue;
        }

        // Here we received data on the socket, see if it's a very first message from the client
        // which is action:connect. All control messages begin with 0

        char buff[128];
        const char* p = inet_ntop(addr.sin6_family, &addr.sin6_addr, buff, sizeof(buff));

        if (p == nullptr)
        {
            close(client);
            bBind = true;
            continue;
        }

        // convert ipv4 mapped ipv6 address
        string ip = buff;
        string pref = "::ffff:";

        if (ip.find(pref) != string::npos)
        {
            ip = ip.substr(ip.find(pref) + pref.length());
        }

        if (packet[0] == 0 &&
            strncmp(ACTION_CONNECT.c_str(), &packet[1], ACTION_CONNECT.length()) == 0)
        {
            if (connect(client, (sockaddr *)&addr, addrlen) == 0)
            {
                // Get desired location
                auto location = string(packet+1, n-1);
                std::size_t semicolonPos = location.find(';');

                if (semicolonPos != std::string::npos)
                {
                    // Extract the substring after the semicolon
                    std::string loc = location.substr(semicolonPos + 1);

                    // Print the extracted location
                    std::cout << "Extracted location: " << loc << std::endl;
                    thread* proxy = new thread(ProxyClient, client, packet, n, loc);
                    lock_guard<mutex> lock(Mutex);
                    threads.push_back(proxy);
                }
            }
            else
            {
                close(client);
            }

            bBind = true;
        }
    }
    close(client);
    // Clean up CURL handle
    curl_easy_cleanup(curl);
    return 0;
}

