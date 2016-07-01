package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.util.ArrayList;
import java.util.List;

class Catcher implements RawDataChannel {
    private final List<RawData> messages = new ArrayList<>();
    private final Object lock = new Object();

    @Override
    public void receiveData(RawData raw) {
        synchronized (lock) {
            messages.add(raw);
            lock.notifyAll();
        }
    }

    void blockUntilSize(int expectedSize) throws InterruptedException {
        synchronized (lock) {
            while (messages.size() < expectedSize) {
                lock.wait();
            }
        }
    }

    RawData getMessage(int index) {
        synchronized (lock) {
            return messages.get(index);
        }
    }
}
