/*
 * BlockingQ.hpp
 *
 *  Created on: Jan 4, 2019
 *      Author: Daniel
 */

#ifndef BLOCKINGQ_HPP_
#define BLOCKINGQ_HPP_

#include <queue>
#include <pthread.h>

template <class T>
class BlockingQ
{
public:
	BlockingQ();
	virtual ~BlockingQ(){};

	void push(const T& item);
	T pop();

private:
	pthread_mutex_t qMutex;
	pthread_cond_t wakeup;
	std::queue<T> q;
};

template<typename T>
BlockingQ<T>::BlockingQ()
{
	pthread_mutex_init(&qMutex, NULL);
	pthread_cond_init(&wakeup, NULL);
	q = std::queue<T>();
}

template<typename T>
void BlockingQ<T>::push(const T& item)
{
	pthread_mutex_lock(&qMutex);
		q.push(item);
	pthread_mutex_unlock(&qMutex);
	pthread_cond_signal(&wakeup);
}

template<typename T>
T BlockingQ<T>::pop()
{
	pthread_mutex_lock(&qMutex);
		while(q.empty())
		{
			pthread_cond_wait(&wakeup, &qMutex);
		}
		T item = q.front();
		q.pop();
	pthread_mutex_unlock(&qMutex);
	return item;
}
#endif /* BLOCKINGQ_HPP_ */
