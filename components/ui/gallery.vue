<template lang="pug">
	.gallery
		button.gallery-button.gallery-left(
			@mousedown="left"
			@touchstart="left"
			@contextmenu="contextmenu($event)"
			v-if="leftButtonVisible"
		)
		button.gallery-button.gallery-right(
			@mousedown="right"
			@touchstart="right"
			@contextmenu="contextmenu($event)"
			v-if="rightButtonVisible"
		)
		.gallery-outer(ref="gallery")
			.gallery-inner
				.gallery-image(
					v-for="image in images"
					:key="image"
					:style="{backgroundImage:`url(\"${image}\")`}"
					@click="clickImage(image)"
					:class="{selected:selected ? image===selected : image===images[0]}"
				)
</template>
<style scoped lang="scss">
.gallery{
	position:relative;
	height:200px
}
.gallery-outer{
	overflow-x:hidden;
}
.gallery-inner{
	display:flex;
}
.gallery-image{
	width:200px;
	height:200px;
	min-width:200px;
	background-size:contain;
	background-position:center;
	background-repeat:no-repeat;
	margin-left:20px;
	border:1px solid #ccc;
	cursor:pointer
}
.gallery-image:hover{
	border-color:orange
}
.gallery-button{
	position:absolute;
	top:0px;
	bottom:0px;
	width:100px;
	border:0px;
	border-radius:0px;
	background-position:center;
	background-repeat:no-repeat;
	background-size:50%;
	background-color:rgba(0,0,0,0.7);
	cursor:pointer
}
.gallery-button:hover{
	background-color:rgba(0,0,0,0.5);	
}
.gallery-button:active{
	background-color:rgba(0,0,0,0.8);	
}
.gallery-image.selected{
	border-color:blue !important
}
.gallery-left{
	background-image:url("/prev.png");
}	
.gallery-right{
	background-image:url("/next.png");		
	right:0px
}
@media (max-width: 800px) {
	.gallery-button{
		width:50px
	}
	.gallery-image{
		width:100px;
		height:100px;
		min-width:100px;
		margin-left:10px
	}
	.gallery{
		height:100px			
	}
}
</style>
<script>
	const scrollStep = 10
	
	export default {
		props: ['images'],
		data(){
			return {
				leftButtonVisible:false,
				rightButtonVisible:false,
				status:null,
				selected:null
			}	
		},
		mounted(){
			let url = document.location.href
			let timerAnimation = setInterval(() => this.tick(), 10)

			let handler = () => this.status = null
			let resizeHandler = () => this.resize()

			setTimeout(resizeHandler, 500)

			window.addEventListener('touchend', handler)
			window.addEventListener('mouseup',  handler)
			window.addEventListener('resize', resizeHandler)
				
			let timerLifeCycle = setInterval(() => {
				if(url != document.location.href)
					clearInterval(timerAnimation),
					clearInterval(timerLifeCycle),
					window.removeEventListener('touchend', handler),
					window.removeEventListener('mouseup',  handler),
					window.removeEventListener('resize', resizeHandler)
			},500)
		},
		methods:{
			resize(){
				let gallery = this.$refs.gallery
				this.leftButtonVisible  = gallery.scrollLeft
				this.rightButtonVisible = gallery.scrollLeft !== gallery.scrollWidth - gallery.clientWidth			
			},
			tick(){
				let gallery = this.$refs.gallery

				if(this.status === 'left'){
					if(gallery.scrollLeft < scrollStep){
						gallery.scrollLeft = 0
						this.leftButtonVisible = false
						console.log(0)
					}else{
						gallery.scrollLeft -= scrollStep			
						console.log('-')
					}
				}else if(this.status === 'right'){
					if(gallery.scrollWidth - gallery.scrollLeft - gallery.clientWidth < scrollStep){
						gallery.scrollLeft = gallery.scrollWidth - gallery.clientWidth			
						this.rightButtonVisible = false
						console.log('max')
					}else{
						gallery.scrollLeft += scrollStep			
						console.log('+')
					}
				}	
			},
			left(){
				this.status = 'left'
				this.rightButtonVisible = true
			},
			right(){
				this.status = 'right'
				this.leftButtonVisible = true
			},
			contextmenu(event){
				event.preventDefault()
     			event.stopPropagation()
				return false
			},
			clickImage(image){
				this.$emit('change',image)
				this.selected = image
			}
		}
	}
</script>
