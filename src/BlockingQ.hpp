/*
 * BlockingQ.hpp
 *
 *  Created on: Jan 4, 2019
 *      Author: Daniel
 */

#ifndef BLOCKINGQ_HPP_
#define BLOCKINGQ_HPP_

#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <exception>

template <class T>
class BlockingQ
{
public:
	BlockingQ();
	virtual ~BlockingQ(){};

	void push(T& item);
	void push(const T& item);
	T pop();
	void interrupt();
	void clear();
	
private:
	std::condition_variable wakeup;
	std::mutex qtex;
	std::vector<T> q;
	std::atomic<bool> interrupted;
};

template<typename T>
BlockingQ<T>::BlockingQ() :
q(),
qtex(),
wakeup(),
interrupted(false)
{
}

template<typename T>
void BlockingQ<T>::push(T& item)
{
	{
		std::unique_lock<std::mutex> qLock(qtex);
		q.push_back(std::move(item));
	}
	wakeup.notify_all();
}

template<typename T>
void BlockingQ<T>::push(const T& item)
{
	{
		std::unique_lock<std::mutex> qLock(qtex);
		q.push_back(item);
	}
	wakeup.notify_all();
}

template<typename T>
T BlockingQ<T>::pop()
{
	std::unique_lock<std::mutex> qLock(qtex);
	while (q.empty())
	{
		if(interrupted)
		{
			throw std::runtime_error("Blocking Q was interrupted");
		}
		wakeup.wait(qLock);
	}
	
	T item = std::move(q[0]);
	q.erase(q.begin());
	return std::move(item);
}

template<typename T>
void BlockingQ<T>::interrupt()
{
	interrupted = true;
	wakeup.notify_all();
}

template<typename T>
void BlockingQ<T>::clear()
{
	std::unique_lock<std::mutex> qLock(qtex);
	q.clear();
}
#endif /* BLOCKINGQ_HPP_ */
