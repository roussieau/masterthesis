import React from 'react';
import logo from './logo.svg';
import './App.css';

class App extends React.Component {
    constructor(props) {
        super(props);
        this.handleClick = this.handleClick.bind(this);
        this.handleChange = this.handleChange.bind(this);
    }

    handleClick(e) {
        this.refs.fileUploader.click();
    }

    handleChange(e) {
        console.log(e.target.files[0]);
    }

    render() {
        return (
            <div className="card" onClick={this.handleClick}>
                <input id="malware"
                    type="file"
                    ref="fileUploader"
                    onChange={this.handleChange}
                    style={{display: "none"}}/> 
                <i className="fas fa-microscope" id="microscope"></i>
                <h5> Click to scan </h5>
            </div>
        );
    }
}

export default App;
