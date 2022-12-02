package org.eclipse.californium.core.network.stack;


import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.elements.EndpointContext;

public class BaseConnectionOrientedCoapStack extends BaseCoapStack implements ConnectionOrientedCoapStack{

	protected BaseConnectionOrientedCoapStack(Outbox outbox) {
		super(outbox);
	}
	
	@Override
	protected StackBottomAdapter createStackBottomAdapter() {
		return new ConnectionOrientedStackBottomAdapter();
	}
	
	@Override
	protected StackTopAdapter createStackTopAdapter() {
		return new ConnectionOrientedStackTopAdapter();
	}

	protected class ConnectionOrientedStackTopAdapter extends StackTopAdapter implements ConnectionOrientedLayer {
		@Override
		public void connected(EndpointContext context) {
			// TODO should we raise this event out of the stack ? 
		}
		@Override
		public void disconnected(EndpointContext context) {
			// TODO should we raise this event out of the stack ?
		}
	}

	protected class ConnectionOrientedStackBottomAdapter extends StackBottomAdapter implements ConnectionOrientedLayer{
		@Override
		public void connected(EndpointContext context) {
			if (upperLayer instanceof ConnectionOrientedLayer) {
				((ConnectionOrientedLayer) upperLayer).connected(context);	
			}
		}
		@Override
		public void disconnected(EndpointContext context) {
			if (upperLayer instanceof ConnectionOrientedLayer) {
				((ConnectionOrientedLayer) upperLayer).disconnected(context);	
			}
		}
	}

	protected void setLayers(Layer[] specificLayers) {
		// TODO should we check there is only Connection Oriented Layer ?
		super.setLayers(specificLayers);
	}
	
	protected void setLayers(ConnectionOrientedLayer[] specificLayers) {
		super.setLayers(specificLayers);
	}

	@Override
	public void connected(org.eclipse.californium.elements.EndpointContext context) {
		((ConnectionOrientedLayer)bottom).connected(context);
	}

	@Override
	public void disconnected(org.eclipse.californium.elements.EndpointContext context) {
		((ConnectionOrientedLayer)bottom).disconnected(null);
	}
}
