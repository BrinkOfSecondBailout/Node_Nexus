/* script.js */

const name = document.getElementById('user_name').value.trim();
const age = document.getElementById('user_age').value.trim();
	
const current_bio = document.getElementById('current_bio');
current_bio.innerText = `${name} / ${age} years old`;

function updateUser() {

	const name = document.getElementById('user_name').value.trim();
	const age = document.getElementById('user_age').value.trim();
	const responseDiv = document.getElementById('response');
	
	console.log(name, age);
	
	if (name == 'John Doe' && age == 30) {
		responseDiv.innerText = 'Please provide inputs to update your profile';
	} else {

	fetch('/api/user', {
		method: 'PATCH',
		headers: {
			'Content-Type': 'application/x-www-form-urlencoded'
		},
		body: `name=${encodeURIComponent(name)}&age=${encodeURIComponent(age)}`
	})
	.then(response => response.json())
	.then(data => {
		responseDiv.innerText = `Successfully updated bio to: name - "${data.name}" age - "${data.age}"`;
		current_bio.innerText = `${data.name} / ${data.age} years old`;
		document.getElementById('user_name').value = data.name;
		document.getElementById('user_age').value = data.age;
	})
	.catch(error => {
		responseDiv.innerText = `Error: ${error.message}`;
	});
	}
}

function deleteUser() {
	const responseDiv = document.getElementById('response');
	fetch('/api/user', {
		method: 'DELETE'
	})
	.then(response => response.text())
	.then(data => {
		responseDiv.innerText = data;
		
	
		document.getElementById('user_name').value = 'John Doe';
		document.getElementById('user_age').value = 30;
		current_bio.innerText = 'John Doe / 30 years old';
	})
	.catch(error => {
		responseDiv.innerText = `Error: ${error.message}`;
	});
}


