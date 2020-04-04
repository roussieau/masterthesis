def plotSVC(title):
	# create a mesh to plot in
	x_min, x_max = X[:, 0].min() — 1, X[:, 0].max() + 1
	y_min, y_max = X[:, 1].min() — 1, X[:, 1].max() + 1
	h = (x_max / x_min)/100
	xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))
	plt.subplot(1, 1, 1)
	Z = svc.predict(np.c_[xx.ravel(), yy.ravel()])
	Z = Z.reshape(xx.shape)
	plt.contourf(xx, yy, Z, cmap=plt.cm.Paired, alpha=0.8)
	plt.scatter(X[:, 0], X[:, 1], c=y, cmap=plt.cm.Paired)
	plt.xlabel(‘Sepal length’)
	plt.ylabel(‘Sepal width’)
	plt.xlim(xx.min(), xx.max())
	plt.title(title)
	plt.show()