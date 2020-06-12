import React from 'react';
import axios from 'axios';
import logo from './logo.svg';
import './App.css';

class App extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            fileName: null,
            res: null,
        }
        this.handleClick = this.handleClick.bind(this);
        this.handleChange = this.handleChange.bind(this);
    }

    handleClick(e) {
        this.refs.fileUploader.click();
    }

    handleChange(e) {
        let file = e.target.files[0];
        const data = new FormData()
        data.append('file', file)
        axios.post(
            'http://localhost:8888/upload',
             data,
        ).then(res => {
            this.setState({
                res: res.data,
                fileName: file.name,
            });
        });
    }

    render() {
        let msg = null;
        if (this.state.fileName) {
            msg = <p> The file <b>{this.state.fileName}</b> has been detected as <b>{this.state.res.message} </b> ! <br/>
                    Extraction time (s): {this.state.res.extraction_time}. <br/>
                    Classification time (s): {this.state.res.classification_time}.
                </p>;
        }

        return (
        <div className="row">
            <div className="col-md-8">
                <p>As part of our master's thesis at the “Université Catholique
                de Louvain”, we developed this tool that uses machine learning
                to determine whether malware is packed.</p>
            </div>
            <div className="card col-md-4" onClick={this.handleClick}>
                <input id="malware"
                    type="file"
                    ref="fileUploader"
                    onChange={this.handleChange}
                    style={{display: "none"}}/> 
                <i className="fas fa-microscope" id="microscope"></i>
                <h5> Click to scan </h5>
            </div>
            {msg}
        </div>
        );
    }
}

export default App;
