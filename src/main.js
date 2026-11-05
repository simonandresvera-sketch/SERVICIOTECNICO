//TIP With Search Everywhere, you can find any action, file, or symbol in your project. Press <shortcut actionId="Shift"/> <shortcut actionId="Shift"/>, type in <b>terminal</b>, and press <shortcut actionId="EditorEnter"/>. Then run <shortcut raw="npm run dev"/> in the terminal and click the link in its output to open the app in the browser.
export function setupCounter(element) {
	//TIP Try <shortcut actionId="GotoDeclaration"/> on <shortcut raw="counter"/> to see its usages. You can also use this shortcut to jump to a declaration – try it on <shortcut raw="counter"/> on line 13.
	let counter = 0;
	const adjustCounterValue = value => {
		if (value >= 100) return value - 100;
		if (value <= -100) return value + 100;
		return value;
	};

	const setCounter = value => {
		counter = adjustCounterValue(value);
		//TIP WebStorm has lots of inspections to help you catch issues in your project. It also has quick fixes to help you resolve them. Press <shortcut actionId="ShowIntentionActions"/> on <shortcut raw="text"/> and choose <b>Inline variable</b> to clean up the redundant code.
		const text = `${counter}`;
		element.innerHTML = text;
	};

	document.getElementById('increaseByOne').addEventListener('click', () => setCounter(counter + 1));
	document.getElementById('decreaseByOne').addEventListener('click', () => setCounter(counter - 1));
	document.getElementById('increaseByTwo').addEventListener('click', () => setCounter(counter + 2));
	//TIP To find text strings in your project, press <shortcut actionId="FindInPath"/> and type in <b>counter</b> – you’ll get all matches in one place.
	setCounter(0);
}

// TIP To find text strings in your project, press <shortcut actionId="FindInPath"/> and type in <b>counter</b> – you’ll get all matches in one place.
setupCounter(document.getElementById('counter-value'));