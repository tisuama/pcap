BUILD_PATH=./build
def:
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o ldapexpr.o src/filter/ldapexpr.c
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o filter.o src/filter/filter.c -I src/pcap/
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o xtest.o src/xtest/xtest.c
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o pcap_manager.o src/pcap/pcap_manager.c -I src/filter/
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o main.o src/demo/main.c -I src/pcap/ -I src/filter/
	gcc -Wall -g -fprofile-arcs -ftest-coverage -c -o test_pcap.o src/test/test_pcap.c -I src/pcap/ -I src/filter/ -I src/xtest/
	gcc -Wall -o test_pcap test_pcap.o filter.o pcap_manager.o xtest.o ldapexpr.o -lgcov

clean: 
	rm -f *.o *.gcda *.gcno *.gcov  test_pcap.info
	rm -f *.yml
	rm -f test
	rm -rf pcap
	rm -rf ldap
	rm -rf test_pcap

test: def
	./test_pcap

check:
	valgrind --leak-check=full -v ./pcap

lcov:
	lcov -d ./ -t 'test_pcap' -o 'test_pcap.info' -b . -c
	genhtml -o pcap_web test_pcap.info

pcap:
	gcc -g -c -o ldapexpr.o src/filter/ldapexpr.c
	gcc -g -c -o filter.o src/filter/filter.c -I src/pcap/
	gcc -g -c -o pcap_manager.o src/pcap/pcap_manager.c -I src/filter/
	gcc -g -c -o main.o src/demo/main.c -I src/pcap/ -I src/filter/
	gcc -o pcap main.o pcap_manager.o ldapexpr.o filter.o

ldap:
	gcc -Wall -g -o ldap src/ldapexpr/ldapexpr.c

.PHONY: def clean ut test pcap ldap
