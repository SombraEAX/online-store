<template lang="pug">
	nuxt-link.item(:to="link")
		.item-image(:style="{backgroundImage:p(image)}") &nbsp;
		.item-name {{name}}
		.item-price {{formatPrice(price)}} $
</template>
<style scoped lang="scss">
.item{
	width:25vw;
	height:30vw;
	border:1px solid #ccc;
	display:inline-flex;
	flex-direction:column;
	margin:10px;
	color:#000;
	text-decoration:none;
	font-weight:bold;
}
.item:hover{
	border-color:#000099
}
.item-image{
	background-repeat:no-repeat;
	background-position:center;
	background-size:contain;
	max-width:100%;
	flex:1
}
.item-name,.item-price{
	margin-left:20px;
	margin-right:20px;
}
.item-name{
	margin-top:20px;
	margin-bottom:20px;
	color:#0000e6
}
.item-price{
	margin-bottom:20px;
	font-size:20px
}
@media (max-width:1200px){
	.item{
		width:24vw;
		height:30vw
	}
}
@media (max-width:800px){
	.item{
		width:42vw;
		height:50vw
	}
}
@media (max-width:630px){
	.item{
		width:40vw;
		height:50vw
	}
}
@media (max-width:500px){
	.item{
		width:43vw;
		height:50vw
	}
}
@media (max-width:430px){
	.item{
		width:90vw;
		height:70vw
	}
}
</style>
<script>
	import {formatPrice} from '../../lib.js'
	
	export default {
		props:['image','name','price','link'],
		methods:{
			p(url){
				return `url("${url}")`
			},
			formatPrice
		}
	}
</script>
