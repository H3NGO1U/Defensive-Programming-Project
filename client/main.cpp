#include <string>
#include "client.h"
int main(int argc, char* argv[]) {
	try {

		Client client;
		client.start();
	
	}


	catch (std::exception& e) {
		std::cerr << "Exception in thread " << e.what();
	}
}


