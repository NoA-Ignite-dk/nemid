const { getNemIDAuthContext } = require('@noaignite/nemid');
const axios = require('axios')

;(async function () {
	const { data: parameters } = await axios('http://localhost:8000/authenticate');

	const context = getNemIDAuthContext(parameters);
	// optional styling
	context.element.style.border = 0;
	context.element.style.width = '320px';
	context.element.style.height = '480px';

	document.body.appendChild(context.element);

	const result = await context.done;

	const { data } = await axios.post('http://localhost:8000/authenticate/verify', { content: result });

	document.body.removeChild(context.element);

	console.log(data);
})();
