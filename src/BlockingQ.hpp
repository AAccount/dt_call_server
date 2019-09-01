/*
 * BlockingQ.hpp
 *
 *  Created on: Jan 4, 2019
 *      Author: Daniel
 */

#ifndef BLOCKINGQ_HPP_
#define BLOCKINGQ_HPP_

#include <queue>
#include <mutex>
#include <condition_variable>

template <class T>
class BlockingQ
{
public:
	BlockingQ();
	virtual ~BlockingQ(){};

	void push(const T& item);
	T pop();

private:
	std::condition_variable wakeup;
	std::mutex qtex;
	std::queue<T> q;
};

template<typename T>
BlockingQ<T>::BlockingQ() :
q(),
qtex(),
wakeup()
{
}

template<typename T>
void BlockingQ<T>::push(const T& item)
{
	{
		std::unique_lock<std::mutex> qLock(qtex);
		q.push(item);
	}
	wakeup.notify_all();
}

template<typename T>
T BlockingQ<T>::pop()
{
	std::unique_lock<std::mutex> qLock(qtex);
	while (q.empty())
	{
		wakeup.wait(qLock);
	}
	T item = q.front();
	q.pop();

	return item;
}
#endif /* BLOCKINGQ_HPP_ */
